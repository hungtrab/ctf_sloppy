use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute, queue,
    style::{self, Color},
    terminal,
};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{
    Cmd, CompletionType, ConditionalEventHandler, Config, Context, EditMode, Editor,
    Event as RlEvent, EventContext, EventHandler, Helper, KeyCode as RlKeyCode,
    KeyEvent as RlKeyEvent, Modifiers, RepeatCount,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Submit(String),
    Cancel,
    Exit,
    /// Ctrl+O — toggle full bash/tool output mode.
    ToggleVerboseOutput,
    /// Ctrl+E — show full session history.
    ShowFullHistory,
}

// ─── Slash command popup ──────────────────────────────────────────────────────

/// Show an interactive slash-command picker. Returns the selected command or None.
/// Assumes the terminal is already in raw mode (rustyline owns it).
pub fn show_slash_menu(commands: &[(String, String)]) -> Option<String> {
    let mut stdout = io::stdout();

    let Ok((origin_col, _)) = cursor::position() else {
        return None;
    };

    let (term_width, term_height) = terminal::size().unwrap_or((80, 24));
    let max_visible = 10usize.min(commands.len()).max(1);

    // Reserve `max_visible` item rows + 1 footer row below the cursor by
    // printing blank lines. If the cursor is near the bottom of the
    // terminal this scrolls the screen (shifting the prompt line up too);
    // moving back up by the same amount lands exactly above the popup's
    // first row in either case, so the popup is never clipped/invisible.
    let needed_rows = (max_visible + 1) as u16;
    for _ in 0..needed_rows {
        let _ = stdout.write_all(b"\n");
    }
    let _ = stdout.flush();
    let _ = execute!(stdout, cursor::MoveUp(needed_rows));
    let Ok((_, origin_row)) = cursor::position() else {
        return None;
    };

    let max_visible = max_visible
        .min(term_height.saturating_sub(origin_row + 2) as usize)
        .max(1);
    let popup_row = origin_row + 1;

    let _ = execute!(stdout, cursor::Hide);

    let mut filter = String::new();
    let mut selected = 0usize;
    let mut scroll_offset = 0usize;
    let mut max_rows_rendered = 0u16;

    let result = loop {
        let filtered: Vec<&(String, String)> = if filter.is_empty() {
            commands.iter().collect()
        } else {
            commands
                .iter()
                .filter(|(cmd, _)| {
                    cmd.trim_start_matches('/')
                        .to_lowercase()
                        .contains(filter.to_lowercase().as_str())
                })
                .collect()
        };

        let count = filtered.len();

        if count == 0 {
            selected = 0;
            scroll_offset = 0;
        } else {
            if selected >= count {
                selected = count - 1;
            }
            if selected < scroll_offset {
                scroll_offset = selected;
            }
            if selected >= scroll_offset + max_visible {
                scroll_offset = selected + 1 - max_visible;
            }
        }

        let rows = render_popup(
            &mut stdout,
            &filtered,
            selected,
            scroll_offset,
            max_visible,
            &filter,
            popup_row,
            term_width as usize,
        );

        // Clear any leftover rows from a previous larger render
        if rows < max_rows_rendered {
            for i in rows..max_rows_rendered {
                let _ = queue!(
                    stdout,
                    cursor::MoveTo(0, popup_row + i),
                    terminal::Clear(terminal::ClearType::CurrentLine),
                );
            }
            let _ = io::stdout().flush();
        }
        max_rows_rendered = max_rows_rendered.max(rows);

        // Move cursor back to where it was before the popup.
        let _ = execute!(stdout, cursor::MoveTo(origin_col, origin_row));

        match event::read() {
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Up, ..
            })) => {
                selected = selected.saturating_sub(1);
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Down,
                ..
            })) => {
                if count > 0 && selected + 1 < count {
                    selected += 1;
                }
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Tab, ..
            })) => {
                if count > 0 {
                    selected = (selected + 1) % count;
                }
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            })) => {
                break filtered.get(selected).map(|(cmd, _)| cmd.clone());
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Esc, ..
            })) => {
                break None;
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers,
                ..
            })) if modifiers.contains(KeyModifiers::CONTROL) => {
                break None;
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Backspace,
                ..
            })) => {
                if filter.pop().is_none() {
                    break None;
                }
                selected = 0;
                scroll_offset = 0;
            }
            Ok(Event::Key(KeyEvent {
                code: KeyCode::Char(c),
                modifiers,
                ..
            })) if modifiers == KeyModifiers::NONE || modifiers == KeyModifiers::SHIFT => {
                filter.push(c);
                selected = 0;
                scroll_offset = 0;
            }
            Err(_) => break None,
            _ => {}
        }
    };

    // Clear all rows that the popup ever occupied.
    for i in 0..max_rows_rendered {
        let _ = queue!(
            stdout,
            cursor::MoveTo(0, popup_row + i),
            terminal::Clear(terminal::ClearType::CurrentLine),
        );
    }
    let _ = execute!(stdout, cursor::MoveTo(origin_col, origin_row), cursor::Show);

    result
}

fn render_popup(
    stdout: &mut impl Write,
    filtered: &[&(String, String)],
    selected: usize,
    scroll_offset: usize,
    max_visible: usize,
    filter: &str,
    popup_row: u16,
    term_width: usize,
) -> u16 {
    // " ▶ " / "   " prefix (3 chars) + cmd_col + " " before description
    let cmd_col = 22usize;
    let desc_offset = cmd_col + 4;
    let desc_max = term_width.saturating_sub(desc_offset + 1).max(20);

    let end = (scroll_offset + max_visible).min(filtered.len());
    let visible = &filtered[scroll_offset..end];

    let mut row = popup_row;

    for (i, (cmd, desc)) in visible.iter().enumerate() {
        let real_idx = scroll_offset + i;
        let is_selected = real_idx == selected;

        let cmd_padded = format!("{cmd:<cmd_col$}");
        let desc_lines = wrap_words(desc, desc_max);
        let first_desc = desc_lines.first().map_or("", String::as_str);

        let _ = queue!(
            stdout,
            cursor::MoveTo(0, row),
            terminal::Clear(terminal::ClearType::CurrentLine),
        );

        if is_selected {
            let _ = queue!(
                stdout,
                style::SetBackgroundColor(Color::DarkGrey),
                style::SetForegroundColor(Color::White),
                style::Print(format!(" \u{25b6} {cmd_padded}")),
                style::SetForegroundColor(Color::Grey),
                style::Print(format!(" {first_desc}")),
                style::ResetColor,
            );
        } else {
            let _ = queue!(
                stdout,
                style::SetForegroundColor(Color::Cyan),
                style::Print(format!("   {cmd_padded}")),
                style::SetForegroundColor(Color::DarkGrey),
                style::Print(format!(" {first_desc}")),
                style::ResetColor,
            );
        }
        row += 1;

        // Continuation lines indented to align with the description column
        for extra in desc_lines.iter().skip(1) {
            let _ = queue!(
                stdout,
                cursor::MoveTo(0, row),
                terminal::Clear(terminal::ClearType::CurrentLine),
                style::SetForegroundColor(if is_selected {
                    Color::Grey
                } else {
                    Color::DarkGrey
                }),
                style::Print(format!("{:width$}{extra}", "", width = desc_offset + 1)),
                style::ResetColor,
            );
            row += 1;
        }
    }

    // Footer
    let _ = queue!(
        stdout,
        cursor::MoveTo(0, row),
        terminal::Clear(terminal::ClearType::CurrentLine),
        style::SetForegroundColor(Color::DarkGrey),
    );

    let filter_display = if filter.is_empty() {
        "type to filter".to_string()
    } else {
        format!("filter: {filter}")
    };
    let scroll_info = if filtered.len() > max_visible {
        format!("  [{}/{}]", selected + 1, filtered.len())
    } else {
        String::new()
    };

    let _ = queue!(
        stdout,
        style::Print(format!(
            "   \u{2191}\u{2193} navigate  Enter select  Esc cancel  {filter_display}{scroll_info}"
        )),
        style::ResetColor,
    );

    let _ = stdout.flush();

    // Return total rows rendered (item lines + footer line)
    row - popup_row + 1
}

fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}\u{2026}", &s[..max.saturating_sub(1)])
    }
}

fn wrap_words(s: &str, max_width: usize) -> Vec<String> {
    if max_width < 4 {
        return vec![truncate(s, max_width)];
    }
    if s.len() <= max_width {
        return vec![s.to_string()];
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        let w = if word.len() > max_width {
            &word[..max_width]
        } else {
            word
        };
        if current.is_empty() {
            current = w.to_string();
        } else if current.len() + 1 + w.len() <= max_width {
            current.push(' ');
            current.push_str(w);
        } else {
            lines.push(std::mem::take(&mut current));
            current = w.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Print a full-width horizontal separator to stdout.
pub fn print_separator() {
    let (term_width, _) = terminal::size().unwrap_or((80, 24));
    let border: String = "─".repeat(term_width as usize);
    println!("\x1b[38;2;92;106;114m{border}\x1b[0m");
}

// ─── Slash key handler (triggers popup on empty buffer) ───────────────────────

struct SlashKeyHandler {
    commands: Arc<Vec<(String, String)>>,
}

impl ConditionalEventHandler for SlashKeyHandler {
    fn handle(
        &self,
        _evt: &RlEvent,
        _n: RepeatCount,
        _positive: bool,
        ctx: &EventContext<'_>,
    ) -> Option<Cmd> {
        // Only show picker when the buffer is empty (pressing / at a fresh prompt).
        if !ctx.line().is_empty() {
            return None; // let '/' be inserted normally
        }

        let selected = show_slash_menu(&self.commands);

        selected.map(|cmd| Cmd::Insert(1, format!("{cmd} ")))
    }
}

// ─── SlashCommandHelper (Tab completion + highlight tracking) ─────────────────

struct SlashCommandHelper {
    completions: Vec<String>,
    current_line: RefCell<String>,
}

impl SlashCommandHelper {
    fn new(completions: Vec<String>) -> Self {
        Self {
            completions,
            current_line: RefCell::new(String::new()),
        }
    }

    fn reset_current_line(&self) {
        self.current_line.borrow_mut().clear();
    }

    fn current_line(&self) -> String {
        self.current_line.borrow().clone()
    }

    fn set_current_line(&self, line: &str) {
        let mut cur = self.current_line.borrow_mut();
        cur.clear();
        cur.push_str(line);
    }
}

impl Completer for SlashCommandHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let Some(prefix) = slash_command_prefix(line, pos) else {
            return Ok((0, Vec::new()));
        };

        let matches = self
            .completions
            .iter()
            .filter(|c| c.starts_with(prefix))
            .map(|c| Pair {
                display: c.clone(),
                replacement: c.clone(),
            })
            .collect();

        Ok((0, matches))
    }
}

impl Hinter for SlashCommandHelper {
    type Hint = String;
}

impl Highlighter for SlashCommandHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        self.set_current_line(line);
        Cow::Borrowed(line)
    }

    fn highlight_char(&self, line: &str, _pos: usize, _kind: CmdKind) -> bool {
        self.set_current_line(line);
        false
    }
}

impl Validator for SlashCommandHelper {}
impl Helper for SlashCommandHelper {}

// ─── Ctrl+<key> "trigger a flag and submit" handler ────────────────────────────
// Used by both Ctrl+O (toggle full bash/tool output) and Ctrl+E (show full
// session history) — pressing either accepts the current line so read_line
// can inspect the corresponding flag and return the matching ReadOutcome.

struct CtrlFlagHandler {
    triggered: Arc<AtomicBool>,
}

impl ConditionalEventHandler for CtrlFlagHandler {
    fn handle(
        &self,
        _evt: &RlEvent,
        _n: RepeatCount,
        _positive: bool,
        _ctx: &EventContext<'_>,
    ) -> Option<Cmd> {
        self.triggered.store(true, Ordering::Relaxed);
        Some(Cmd::AcceptLine)
    }
}

// ─── LineEditor ───────────────────────────────────────────────────────────────

pub struct LineEditor {
    prompt: String,
    editor: Editor<SlashCommandHelper, DefaultHistory>,
    ctrl_o_triggered: Arc<AtomicBool>,
    ctrl_e_triggered: Arc<AtomicBool>,
}

impl LineEditor {
    #[must_use]
    // `ctrl_o_triggered` / `ctrl_e_triggered` differ only by the key letter,
    // which is exactly what they describe.
    #[allow(clippy::similar_names)]
    pub fn new(prompt: impl Into<String>, commands: Vec<(String, String)>) -> Self {
        let config = Config::builder()
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .build();

        let completions: Vec<String> = commands.iter().map(|(cmd, _)| cmd.clone()).collect();
        let commands_arc = Arc::new(commands);

        let mut editor = Editor::<SlashCommandHelper, DefaultHistory>::with_config(config)
            .expect("rustyline editor should initialize");
        editor.set_helper(Some(SlashCommandHelper::new(completions)));

        // Ctrl+J / Shift+Enter → literal newline
        editor.bind_sequence(
            RlKeyEvent(RlKeyCode::Char('J'), Modifiers::CTRL),
            EventHandler::Simple(Cmd::Newline),
        );
        editor.bind_sequence(
            RlKeyEvent(RlKeyCode::Enter, Modifiers::SHIFT),
            EventHandler::Simple(Cmd::Newline),
        );

        // Ctrl+O → toggle full bash/tool output mode
        let ctrl_o_triggered = Arc::new(AtomicBool::new(false));
        editor.bind_sequence(
            RlKeyEvent(RlKeyCode::Char('o'), Modifiers::CTRL),
            EventHandler::Conditional(Box::new(CtrlFlagHandler {
                triggered: ctrl_o_triggered.clone(),
            })),
        );

        // Ctrl+E → show full session history
        let ctrl_e_triggered = Arc::new(AtomicBool::new(false));
        editor.bind_sequence(
            RlKeyEvent(RlKeyCode::Char('e'), Modifiers::CTRL),
            EventHandler::Conditional(Box::new(CtrlFlagHandler {
                triggered: ctrl_e_triggered.clone(),
            })),
        );

        // '/' on an empty buffer → show interactive slash command picker
        editor.bind_sequence(
            RlKeyEvent(RlKeyCode::Char('/'), Modifiers::NONE),
            EventHandler::Conditional(Box::new(SlashKeyHandler {
                commands: commands_arc,
            })),
        );

        Self {
            prompt: prompt.into(),
            editor,
            ctrl_o_triggered,
            ctrl_e_triggered,
        }
    }

    pub fn push_history(&mut self, entry: impl Into<String>) {
        let entry = entry.into();
        if entry.trim().is_empty() {
            return;
        }
        let _ = self.editor.add_history_entry(entry);
    }

    pub fn read_line(&mut self) -> io::Result<ReadOutcome> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return self.read_line_fallback();
        }

        print_separator();

        if let Some(helper) = self.editor.helper_mut() {
            helper.reset_current_line();
        }

        match self.editor.readline(&self.prompt) {
            Ok(_line) if self.ctrl_o_triggered.swap(false, Ordering::Relaxed) => {
                writeln!(io::stdout())?;
                Ok(ReadOutcome::ToggleVerboseOutput)
            }
            Ok(_line) if self.ctrl_e_triggered.swap(false, Ordering::Relaxed) => {
                writeln!(io::stdout())?;
                Ok(ReadOutcome::ShowFullHistory)
            }
            Ok(line) => Ok(ReadOutcome::Submit(line)),
            Err(ReadlineError::Interrupted) => {
                let has_input = !self.current_line().is_empty();
                self.finish_interrupted_read()?;
                if has_input {
                    Ok(ReadOutcome::Cancel)
                } else {
                    Ok(ReadOutcome::Exit)
                }
            }
            Err(ReadlineError::Eof) => {
                self.finish_interrupted_read()?;
                Ok(ReadOutcome::Exit)
            }
            Err(error) => Err(io::Error::other(error)),
        }
    }

    fn current_line(&self) -> String {
        self.editor
            .helper()
            .map_or_else(String::new, SlashCommandHelper::current_line)
    }

    fn finish_interrupted_read(&mut self) -> io::Result<()> {
        if let Some(helper) = self.editor.helper_mut() {
            helper.reset_current_line();
        }
        writeln!(io::stdout())
    }

    fn read_line_fallback(&self) -> io::Result<ReadOutcome> {
        let mut stdout = io::stdout();
        write!(stdout, "{}", self.prompt)?;
        stdout.flush()?;

        let mut buffer = String::new();
        let bytes_read = io::stdin().read_line(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(ReadOutcome::Exit);
        }

        while matches!(buffer.chars().last(), Some('\n' | '\r')) {
            buffer.pop();
        }
        Ok(ReadOutcome::Submit(buffer))
    }
}

fn slash_command_prefix(line: &str, pos: usize) -> Option<&str> {
    if pos != line.len() {
        return None;
    }
    let prefix = &line[..pos];
    if prefix.contains(char::is_whitespace) || !prefix.starts_with('/') {
        return None;
    }
    Some(prefix)
}
