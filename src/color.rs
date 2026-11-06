//! Zero-dependency ANSI terminal colors and styling.

use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colors {
    enabled: bool,
}

impl Colors {
    pub fn new(no_color_flag: bool) -> Self {
        let enabled = !no_color_flag
            && env::var_os("NO_COLOR").is_none()
            && env::var("TERM").map(|t| t != "dumb").unwrap_or(true);

        #[cfg(windows)]
        if enabled {
            enable_windows_vt_support();
        }

        Self { enabled }
    }

    #[allow(dead_code)]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn style(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.style("1", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.style("2", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.style("31", text)
    }

    #[allow(dead_code)]
    pub fn green(&self, text: &str) -> String {
        self.style("32", text)
    }

    #[allow(dead_code)]
    pub fn yellow(&self, text: &str) -> String {
        self.style("33", text)
    }

    #[allow(dead_code)]
    pub fn blue(&self, text: &str) -> String {
        self.style("34", text)
    }

    #[allow(dead_code)]
    pub fn magenta(&self, text: &str) -> String {
        self.style("35", text)
    }

    pub fn cyan(&self, text: &str) -> String {
        self.style("36", text)
    }

    pub fn bold_red(&self, text: &str) -> String {
        self.style("1;31", text)
    }

    pub fn bold_green(&self, text: &str) -> String {
        self.style("1;32", text)
    }

    pub fn bold_yellow(&self, text: &str) -> String {
        self.style("1;33", text)
    }

    #[allow(dead_code)]
    pub fn bold_cyan(&self, text: &str) -> String {
        self.style("1;36", text)
    }
}

#[cfg(windows)]
fn enable_windows_vt_support() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5; // -11i32 as u32
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle != 0 && handle != -1 {
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_disabled_when_flag_set() {
        let c = Colors::new(true);
        assert!(!c.enabled());
        assert_eq!(c.red("test"), "test");
        assert_eq!(c.green("test"), "test");
        assert_eq!(c.bold("test"), "test");
    }

    #[test]
    fn color_enabled_formats_ansi() {
        let c = Colors { enabled: true };
        assert_eq!(c.red("hello"), "\x1b[31mhello\x1b[0m");
        assert_eq!(c.bold_green("ok"), "\x1b[1;32mok\x1b[0m");
        assert_eq!(c.bold_yellow("warn"), "\x1b[1;33mwarn\x1b[0m");
        assert_eq!(c.cyan("path"), "\x1b[36mpath\x1b[0m");
        assert_eq!(c.dim("info"), "\x1b[2minfo\x1b[0m");
    }
}
