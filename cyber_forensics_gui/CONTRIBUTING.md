# Contributing to Cyber Forensics Toolkit

Thank you for your interest in contributing to the Cyber Forensics Toolkit! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming and inclusive community for all contributors.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Screenshots or logs if applicable
- Your system information (OS, Python version)
- Any relevant configuration details

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- A clear description of the enhancement
- Why this enhancement would be useful
- Any alternative solutions or features you've considered
- Implementation ideas if you have them

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards below
3. **Test your changes** thoroughly
4. **Update documentation** if needed
5. **Submit a pull request** with a clear description of your changes

## Coding Standards

### Python Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and concise
- Add comments for complex logic

### Code Structure

- Modular design with clear separation of concerns
- Use type hints where appropriate
- Handle errors gracefully with try-except blocks
- Log important events and errors

### Testing

- Write tests for new features
- Ensure all existing tests pass
- Test on Windows 10/11 (primary target platform)

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cyber-forensics-toolkit.git
   cd cyber-forensics-toolkit
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python cyber_forensics_gui.py
   ```

## Project Structure

```
cyber_forensics_gui/
├── cyber_forensics_gui.py      # Main GUI application
├── telegram_bot.py             # Telegram bot integration
├── realtime_monitor.py         # Real-time monitoring daemon
├── ai_anomaly_detection.py     # AI anomaly detection
├── external_api.py             # External API integration
├── memory_analysis.py          # Memory analysis module
├── mft_parser.py               # MFT parser
├── analysis_app/               # Report analysis application
│   ├── analysis_gui.py
│   ├── report_analyzer.py
│   └── requirements.txt
├── requirements.txt            # Python dependencies
├── README.md                   # Main documentation
└── LICENSE                     # MIT License
```

## Commit Messages

Use clear and descriptive commit messages:

- `feat: Add new feature description`
- `fix: Fix bug description`
- `docs: Update documentation`
- `refactor: Refactor code description`
- `test: Add tests for feature`
- `chore: Maintenance tasks`

## Release Process

1. Update version number in relevant files
2. Update CHANGELOG.md with release notes
3. Create a git tag: `git tag -a v8.0.1 -m "Release description"`
4. Push the tag: `git push origin v8.0.1`
5. Create GitHub release with notes

## Security Considerations

- Never commit sensitive data (API keys, passwords, tokens)
- Use environment variables for configuration
- Follow security best practices
- Report security vulnerabilities privately

## Questions?

Feel free to open an issue at https://github.com/elslamonyman15-collab/telegram-sec/issues for any questions about contributing to the project.
