# Changelog

All notable changes to the Cyber Forensics Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Full system scan command enhancement for Telegram bot
- Test suite for all Telegram bot commands

### Changed
- Fixed admin commands to use async subprocess calls
- Fixed services command sc query syntax
- Fixed connections command to avoid API blocking

### Fixed
- AttributeError in MemoryAnalyzer integration
- Unicode encoding issues in test script
- Telegram bot conflict errors

## [8.0.0] - 2026-09-29

### Added
- Deep forensic artifact collection (Registry hives, Memory, MFT, Prefetch, Amcache, SRUM, Shellbags, Jump Lists)
- Full Event Log export (Application, System, Security, PowerShell, TaskScheduler, Defender, BITS, RDP, WMI)
- Telegram bot integration with remote command execution
- Rolling log display with download capability
- AI-powered anomaly detection framework
- Real-time monitoring daemon
- Enhanced batch script with 12 forensic steps
- External API integration (AbuseIPDB, VirusTotal)
- Machine learning dependencies (scikit-learn, numpy, pandas)
- 19 Telegram bot commands with full implementation
- Alert history and tracking system
- Module availability checking with graceful degradation

### Changed
- Migrated to python-telegram-bot 20.x async API
- Enhanced all scanning commands with subprocess integration
- Improved error handling and user feedback

### Fixed
- API compatibility issues with python-telegram-bot
- Coroutine usage in command handlers
- Module import errors with graceful fallback

## [5.0.0] - 2024-01-15

### Added
- Complete GUI redesign with tkinter
- Real-time progress tracking
- Automatic threat detection and severity scoring
- Intelligent recommendations with URL references
- Organized folder structure for reports
- Interactive data display with tables and filtering
- Export to multiple formats (JSON, CSV, PDF)
- Color-coded severity indicators
- Detail panel with recommendations

## [4.0.0] - 2023-10-01

### Added
- Initial release from batch script conversion
- Command-line interface
- Basic security scanning
- Text-based report generation

## [Unreleased]

### Security
- No external network calls by default
- All data collected and stored locally
- No data transmission to external servers
- Opt-in cloud analysis only

## [8.0.0] - 2026-09-29

### Security
- Encrypted configuration storage
- Authorization system for Telegram bot
- Admin privilege enforcement
- Role-based access control

## [Unreleased]

### Performance
- Scan duration optimization
- Memory usage improvements
- CPU impact reduction during idle

## [8.0.0] - 2026-09-29

### Performance
- Background scan execution
- Responsive UI during scans
- Efficient data processing with pandas
