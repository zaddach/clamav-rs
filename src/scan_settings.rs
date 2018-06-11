use std::fmt;

use ffi;

pub struct ScanSettings {
    settings: u32,
}

impl Default for ScanSettings {
    /// Returns the defualt scan settings per libclamav recommendations
    fn default() -> ScanSettings { ScanSettings { settings: ffi::CL_SCAN_STDOPT } }
}

impl fmt::Display for ScanSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = String::new();

        // raw isn't a bitflag, it means "no special handling"
        if self.settings == ffi::CL_SCAN_RAW {
            flags.push_str("CL_SCAN_RAW ");
        }
        if self.settings & ffi::CL_SCAN_ARCHIVE == ffi::CL_SCAN_ARCHIVE {
            flags.push_str("CL_SCAN_ARCHIVE ");
        }
        if self.settings & ffi::CL_SCAN_MAIL == ffi::CL_SCAN_MAIL {
            flags.push_str("CL_SCAN_MAIL ");
        }
        if self.settings & ffi::CL_SCAN_OLE2 == ffi::CL_SCAN_OLE2 {
            flags.push_str("CL_SCAN_OLE2 ");
        }
        if self.settings & ffi::CL_SCAN_BLOCKENCRYPTED == ffi::CL_SCAN_BLOCKENCRYPTED {
            flags.push_str("CL_SCAN_BLOCKENCRYPTED ");
        }
        if self.settings & ffi::CL_SCAN_HTML == ffi::CL_SCAN_HTML {
            flags.push_str("CL_SCAN_HTML ");
        }
        if self.settings & ffi::CL_SCAN_PE == ffi::CL_SCAN_PE {
            flags.push_str("CL_SCAN_PE ");
        }
        if self.settings & ffi::CL_SCAN_BLOCKBROKEN == ffi::CL_SCAN_BLOCKBROKEN {
            flags.push_str("CL_SCAN_BLOCKBROKEN ");
        }
        if self.settings & ffi::CL_SCAN_MAILURL == ffi::CL_SCAN_MAILURL {
            flags.push_str("CL_SCAN_MAILURL ");
        }
        if self.settings & ffi::CL_SCAN_BLOCKMAX == ffi::CL_SCAN_BLOCKMAX {
            flags.push_str("CL_SCAN_BLOCKMAX ");
        }
        if self.settings & ffi::CL_SCAN_ALGORITHMIC == ffi::CL_SCAN_ALGORITHMIC {
            flags.push_str("CL_SCAN_ALGORITHMIC ");
        }
        if self.settings & ffi::CL_SCAN_PHISHING_BLOCKSSL == ffi::CL_SCAN_PHISHING_BLOCKSSL {
            flags.push_str("CL_SCAN_PHISHING_BLOCKSSL ");
        }
        if self.settings & ffi::CL_SCAN_PHISHING_BLOCKCLOAK == ffi::CL_SCAN_PHISHING_BLOCKCLOAK {
            flags.push_str("CL_SCAN_PHISHING_BLOCKCLOAK ");
        }
        if self.settings & ffi::CL_SCAN_ELF == ffi::CL_SCAN_ELF {
            flags.push_str("CL_SCAN_ELF ");
        }
        if self.settings & ffi::CL_SCAN_PDF == ffi::CL_SCAN_PDF {
            flags.push_str("CL_SCAN_PDF ");
        }
        if self.settings & ffi::CL_SCAN_STRUCTURED == ffi::CL_SCAN_STRUCTURED {
            flags.push_str("CL_SCAN_STRUCTURED ");
        }
        if self.settings & ffi::CL_SCAN_STRUCTURED_SSN_NORMAL == ffi::CL_SCAN_STRUCTURED_SSN_NORMAL
        {
            flags.push_str("CL_SCAN_STRUCTURED_SSN_NORMAL ");
        }
        if self.settings & ffi::CL_SCAN_STRUCTURED_SSN_STRIPPED
            == ffi::CL_SCAN_STRUCTURED_SSN_STRIPPED
        {
            flags.push_str("CL_SCAN_STRUCTURED_SSN_STRIPPED ");
        }
        if self.settings & ffi::CL_SCAN_PARTIAL_MESSAGE == ffi::CL_SCAN_PARTIAL_MESSAGE {
            flags.push_str("CL_SCAN_PARTIAL_MESSAGE ");
        }
        if self.settings & ffi::CL_SCAN_HEURISTIC_PRECEDENCE == ffi::CL_SCAN_HEURISTIC_PRECEDENCE {
            flags.push_str("CL_SCAN_HEURISTIC_PRECEDENCE ");
        }
        if self.settings & ffi::CL_SCAN_BLOCKMACROS == ffi::CL_SCAN_BLOCKMACROS {
            flags.push_str("CL_SCAN_BLOCKMACROS ");
        }
        if self.settings & ffi::CL_SCAN_ALLMATCHES == ffi::CL_SCAN_ALLMATCHES {
            flags.push_str("CL_SCAN_ALLMATCHES ");
        }
        if self.settings & ffi::CL_SCAN_SWF == ffi::CL_SCAN_SWF {
            flags.push_str("CL_SCAN_SWF ");
        }
        if self.settings & ffi::CL_SCAN_PARTITION_INTXN == ffi::CL_SCAN_PARTITION_INTXN {
            flags.push_str("CL_SCAN_PARTITION_INTXN ");
        }
        if self.settings & ffi::CL_SCAN_XMLDOCS == ffi::CL_SCAN_XMLDOCS {
            flags.push_str("CL_SCAN_XMLDOCS ");
        }
        if self.settings & ffi::CL_SCAN_HWP3 == ffi::CL_SCAN_HWP3 {
            flags.push_str("CL_SCAN_HWP3 ");
        }
        if self.settings & ffi::CL_SCAN_FILE_PROPERTIES == ffi::CL_SCAN_FILE_PROPERTIES {
            flags.push_str("CL_SCAN_FILE_PROPERTIES ");
        }
        if self.settings & ffi::CL_SCAN_PERFORMANCE_INFO == ffi::CL_SCAN_PERFORMANCE_INFO {
            flags.push_str("CL_SCAN_PERFORMANCE_INFO ");
        }
        if self.settings & ffi::CL_SCAN_INTERNAL_COLLECT_SHA == ffi::CL_SCAN_INTERNAL_COLLECT_SHA {
            flags.push_str("CL_SCAN_INTERNAL_COLLECT_SHA ");
        }
        write!(f, "{:#X}: {}", self.settings, flags.trim_right())
    }
}

pub struct ScanSettingsBuilder {
    current: u32,
}

impl ScanSettingsBuilder {
    pub fn new() -> Self {
        ScanSettingsBuilder {
            current: ffi::CL_SCAN_STDOPT,
        }
    }

    pub fn build(&self) -> ScanSettings {
        ScanSettings {
            settings: self.current,
        }
    }

    /// Disable support for special files.
    pub fn clear(&mut self) -> &mut Self {
        self.current = ffi::CL_SCAN_RAW;
        self
    }

    /// Set a flag explicitly
    pub fn with_flag(&mut self, flag: u32) -> &mut Self {
        self.current |= flag;
        self
    }

    /// Enable transparent scanning of various archive formats.
    pub fn enable_archive(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_ARCHIVE;
        self
    }

    /// Enable support for mail files.
    pub fn enable_mail(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_MAIL;
        self
    }

    /// Enable support for mail URL scanning.
    pub fn enable_mail_url(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_MAILURL;
        self
    }

    /// Enable support for OLE2 containers (used by MS Office and .msi files).
    pub fn enable_ole2(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_OLE2;
        self
    }

    /// With this flag the library will mark encrypted archives as viruses (Encrypted.Zip, Encrypted.RAR).
    pub fn block_encrypted(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_BLOCKENCRYPTED;
        self
    }

    /// Enable HTML normalisation (including ScrEnc decryption).
    pub fn enable_html(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_HTML;
        self
    }

    /// Enable deep scanning of Portable Executable files and allows libclamav to unpack executables compressed with run-time unpackers.
    pub fn enable_pe(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_PE;
        self
    }

    /// Try to detect broken executables and mark them as Broken.Executable.
    pub fn block_broken_executables(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_BLOCKBROKEN;
        self
    }

    ///  Mark archives as viruses if maxfiles, maxfilesize, or maxreclevel limit is reached.
    pub fn block_max_limit(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_BLOCKMAX;
        self
    }

    /// Enable algorithmic detection of viruses.
    pub fn enable_algorithmic(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_ALGORITHMIC;
        self
    }

    /// Enable phishing module: always block SSL mismatches in URLs.
    pub fn enable_phishing_blockssl(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_PHISHING_BLOCKSSL;
        self
    }

    /// Enable phishing module: always block cloaked URLs.
    pub fn enable_phishing_blockcloak(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_PHISHING_BLOCKCLOAK;
        self
    }

    /// Enable support for ELF files.
    pub fn enable_elf(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_ELF;
        self
    }

    /// Enable scanning within PDF files.
    pub fn enable_pdf(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_PDF;
        self
    }

    /// Enable the DLP module which scans for credit card and SSN numbers.
    pub fn enable_structured(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_STRUCTURED;
        self
    }

    /// Enable search for SSNs formatted as xx-yy-zzzz.
    pub fn enable_structured_ssn_normal(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_STRUCTURED_SSN_NORMAL;
        self
    }

    /// Enable search for SSNs formatted as xxyyzzzz.
    pub fn enable_structured_ssn_stripped(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_STRUCTURED_SSN_STRIPPED;
        self
    }

    /// Enable scanning of RFC1341 messages split over many emails.
    ///
    /// You will need to periodically clean up $TemporaryDirectory/clamav-partial directory.
    pub fn enable_partial_message(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_PARTIAL_MESSAGE;
        self
    }

    /// Allow heuristic match to take precedence. When enabled, if a heuristic scan (such
    /// as phishingScan) detects a possible virus/phish it will stop scan immediately.
    ///
    /// Recommended, saves CPU scan-time. When disabled, virus/phish detected by heuristic
    /// scans will be reported only at the end of a scan. If an archive contains both a
    /// heuristically detected virus/phishing, and a real malware, the real malware will be
    /// reported.
    pub fn enable_heuristic_precedence(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_HEURISTIC_PRECEDENCE;
        self
    }

    /// OLE2 containers, which contain VBA macros will be marked infected (Heuris-tics.OLE2.ContainsMacros).
    pub fn block_macros(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_BLOCKMACROS;
        self
    }

    /// Enable scanning within SWF files, notably compressed SWF.
    pub fn enable_swf(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_SWF;
        self
    }

    /// Enable scanning of XML docs.
    pub fn enable_xmldocs(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_XMLDOCS;
        self
    }

    /// Enable scanning of HWP3 files.
    pub fn enable_hwp3(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_HWP3;
        self
    }

    /// Enable scanning of file properties.
    pub fn enable_file_properties(&mut self) -> &mut Self {
        self.current |= ffi::CL_SCAN_FILE_PROPERTIES;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_to_standard_opts() {
        let settings = ScanSettingsBuilder::new().build();
        assert_eq!(settings.settings, ffi::CL_SCAN_STDOPT);
    }

    #[test]
    fn builder_clear_success() {
        let settings = ScanSettingsBuilder::new().clear().build();
        assert_eq!(settings.settings, 0);
    }

    #[test]
    fn builder_just_pdf_success() {
        let settings = ScanSettingsBuilder::new().clear().enable_pdf().build();
        assert_eq!(settings.settings, ffi::CL_SCAN_PDF);
    }

    #[test]
    fn builder_normal_files_success() {
        let settings = ScanSettingsBuilder::new()
            .clear()
            .enable_pdf()
            .enable_html()
            .enable_pe()
            .build();
        assert_eq!(
            settings.settings,
            ffi::CL_SCAN_PDF | ffi::CL_SCAN_HTML | ffi::CL_SCAN_PE
        );
    }

    #[test]
    fn builder_all_success() {
        let settings = ScanSettingsBuilder::new()
            .clear()
            .enable_algorithmic()
            .enable_archive()
            .enable_elf()
            .enable_file_properties()
            .enable_heuristic_precedence()
            .enable_html()
            .enable_hwp3()
            .enable_mail()
            .enable_mail_url()
            .enable_ole2()
            .enable_partial_message()
            .enable_pdf()
            .enable_pe()
            .enable_phishing_blockcloak()
            .enable_phishing_blockssl()
            .enable_structured()
            .enable_structured_ssn_normal()
            .enable_structured_ssn_stripped()
            .enable_swf()
            .enable_xmldocs()
            .block_broken_executables()
            .block_encrypted()
            .block_macros()
            .block_max_limit()
            .build();
        assert_eq!(
            settings.settings,
            ffi::CL_SCAN_ARCHIVE | ffi::CL_SCAN_MAIL | ffi::CL_SCAN_OLE2
                | ffi::CL_SCAN_BLOCKENCRYPTED | ffi::CL_SCAN_HTML | ffi::CL_SCAN_PE
                | ffi::CL_SCAN_BLOCKBROKEN | ffi::CL_SCAN_MAILURL
                | ffi::CL_SCAN_BLOCKMAX | ffi::CL_SCAN_ALGORITHMIC
                | ffi::CL_SCAN_PHISHING_BLOCKSSL | ffi::CL_SCAN_PHISHING_BLOCKCLOAK
                | ffi::CL_SCAN_ELF | ffi::CL_SCAN_PDF | ffi::CL_SCAN_STRUCTURED
                | ffi::CL_SCAN_STRUCTURED_SSN_NORMAL
                | ffi::CL_SCAN_STRUCTURED_SSN_STRIPPED | ffi::CL_SCAN_PARTIAL_MESSAGE
                | ffi::CL_SCAN_HEURISTIC_PRECEDENCE | ffi::CL_SCAN_BLOCKMACROS
                | ffi::CL_SCAN_SWF | ffi::CL_SCAN_XMLDOCS | ffi::CL_SCAN_HWP3
                | ffi::CL_SCAN_FILE_PROPERTIES
        );
    }

    #[test]
    fn display_settings_raw_success() {
        let string_settings = ScanSettings {
            settings: ffi::CL_SCAN_RAW,
        }.to_string();
        assert_eq!(string_settings, "0x0: CL_SCAN_RAW");
    }

    #[test]
    fn display_settings_standard_options_success() {
        let string_settings = ScanSettings {
            settings: ffi::CL_SCAN_STDOPT,
        }.to_string();
        assert!(string_settings.contains("CL_SCAN_ARCHIVE"));
        assert!(string_settings.contains("CL_SCAN_MAIL"));
        assert!(string_settings.contains("CL_SCAN_OLE2"));
        assert!(string_settings.contains("CL_SCAN_PDF"));
        assert!(string_settings.contains("CL_SCAN_HTML"));
        assert!(string_settings.contains("CL_SCAN_PE"));
        assert!(string_settings.contains("CL_SCAN_ALGORITHMIC"));
        assert!(string_settings.contains("CL_SCAN_ELF"));
        assert!(string_settings.contains("CL_SCAN_SWF"));
        assert!(string_settings.contains("CL_SCAN_XMLDOCS"));
        assert!(string_settings.contains("CL_SCAN_HWP3"));
    }

    #[test]
    fn settings_default_to_standard() {
        let settings: ScanSettings = Default::default();
        assert_eq!(settings.settings, ffi::CL_SCAN_STDOPT);
    }
}
