# Contributing to IP Ports Scanner

🎉 Thank you for your interest in contributing to IP Ports Scanner! We welcome contributions from the cybersecurity community.

## 🤝 How to Contribute

### Types of Contributions

We welcome several types of contributions:

- 🐛 **Bug Reports**: Found a bug? Please report it!
- ✨ **Feature Requests**: Have an idea for improvement?
- 📖 **Documentation**: Help improve our documentation
- 🧪 **Code Contributions**: Bug fixes, new features, optimizations
- 🌐 **Translations**: Help us support more languages
- �� **Security Issues**: Responsible disclosure of security vulnerabilities

### Getting Started

1. **Fork the Repository**
   ```bash
   # Click the "Fork" button on GitHub
   git clone https://github.com/your-username/IP_Ports_Scanner.git
   cd IP_Ports_Scanner
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python3 -m venv dev-venv
   source dev-venv/bin/activate

   # Install development dependencies
   pip install -r requirements-dev.txt

   # Install pre-commit hooks
   pre-commit install
   ```

3. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-number
   ```

## 🐛 Reporting Bugs

### Before Submitting a Bug Report

- Check if the bug has already been reported in [Issues](https://github.com/yourusername/IP_Ports_Scanner/issues)
- Try to reproduce the issue with the latest version
- Check if it's actually a configuration issue

### How to Submit a Bug Report

Create an issue with the following information:

```markdown
**Bug Description**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '...'
3. Scroll down to '...'
4. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Environment:**
- OS: [e.g., macOS 12.0, Ubuntu 20.04]
- Python Version: [e.g., 3.9.7]
- Browser: [e.g., Chrome 95.0]
- Nmap Version: [e.g., 7.92]

**Scan Configuration:**
- Target subnets: [e.g., 192.168.1.0/24]
- Thread count: [e.g., 10]
- CVE lookup enabled: [Yes/No]

**Additional Context**
Add any other context about the problem here.
```

## ✨ Feature Requests

### Before Submitting a Feature Request

- Check if the feature has already been requested
- Consider if it fits the project's scope and goals
- Think about how it would benefit other users

### How to Submit a Feature Request

Create an issue with the following template:

```markdown
**Feature Summary**
A brief description of the feature you'd like to see.

**Problem Statement**
What problem does this feature solve? What use case does it address?

**Proposed Solution**
How would you like this feature to work?

**Alternative Solutions**
Have you considered any alternative approaches?

**Additional Context**
Any other context, mockups, or examples.
```

## 💻 Code Contributions

### Development Workflow

1. **Choose an Issue**
   - Look for issues labeled `good first issue` for beginners
   - Comment on the issue to indicate you're working on it

2. **Write Code**
   - Follow the coding standards (see below)
   - Write tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run tests
   python -m pytest tests/
   
   # Run linting
   flake8 .
   black --check .
   
   # Test the web interface
   python3 app.py
   # Test CLI interface
   python3 vuln_scan.py -t 127.0.0.1/32
   ```

4. **Submit Pull Request**
   - Push to your fork
   - Create a pull request with a clear description

### Coding Standards

#### Python Code Style

We follow [PEP 8](https://pep8.org/) with some modifications:

```python
# Use Black for formatting
black --line-length 88 .

# Use flake8 for linting
flake8 --max-line-length=88 --extend-ignore=E203,W503 .

# Use isort for imports
isort --profile black .
```

#### Code Quality Guidelines

- **Docstrings**: All functions and classes must have docstrings
- **Type Hints**: Use type hints for function parameters and return values
- **Error Handling**: Proper exception handling with meaningful error messages
- **Logging**: Use the existing logging framework
- **Security**: Follow secure coding practices, especially for network operations

#### Example Code Structure

```python
#!/usr/bin/env python3
"""
Module description here.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ExampleClass:
    """Class description here."""
    
    def __init__(self, parameter: str) -> None:
        """Initialize the class.
        
        Args:
            parameter: Description of parameter
        """
        self.parameter = parameter
    
    def example_method(self, input_data: List[str]) -> Dict[str, str]:
        """Method description here.
        
        Args:
            input_data: List of input strings
            
        Returns:
            Dictionary mapping inputs to outputs
            
        Raises:
            ValueError: If input_data is empty
        """
        if not input_data:
            raise ValueError("input_data cannot be empty")
        
        logger.info(f"Processing {len(input_data)} items")
        
        result = {}
        for item in input_data:
            result[item] = self._process_item(item)
        
        return result
    
    def _process_item(self, item: str) -> str:
        """Private method to process individual items."""
        return item.upper()
```

### Testing Guidelines

#### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch

from vuln_scan import NetworkScanner


class TestNetworkScanner:
    """Test cases for NetworkScanner class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = NetworkScanner(max_threads=5)
    
    def test_discover_hosts_valid_subnet(self):
        """Test host discovery with valid subnet."""
        with patch.object(self.scanner.nm, 'scan') as mock_scan:
            mock_scan.return_value = {
                'scan': {
                    '192.168.1.1': {'status': {'state': 'up'}},
                    '192.168.1.2': {'status': {'state': 'up'}}
                }
            }
            
            hosts = self.scanner.discover_hosts('192.168.1.0/30')
            
            assert len(hosts) == 2
            assert '192.168.1.1' in hosts
            assert '192.168.1.2' in hosts
    
    def test_discover_hosts_invalid_subnet(self):
        """Test host discovery with invalid subnet."""
        hosts = self.scanner.discover_hosts('invalid-subnet')
        assert hosts == []
```

#### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=vuln_scan

# Run specific test file
python -m pytest tests/test_scanner.py

# Run with verbose output
python -m pytest -v
```

### Documentation Guidelines

#### Code Documentation

- Use clear, concise docstrings
- Include parameter types and return values
- Document any exceptions that may be raised
- Provide usage examples for complex functions

#### User Documentation

- Update README.md for new features
- Add examples and screenshots
- Update configuration documentation
- Consider creating tutorial content

## 🔒 Security Contributions

### Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please email security reports to: [security@yourdomain.com](mailto:security@yourdomain.com)

Include the following information:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation (if any)

We will respond within 48 hours and work with you to address any valid security concerns.

### Security Guidelines for Contributors

- Never commit credentials, API keys, or sensitive data
- Follow secure coding practices
- Consider security implications of new features
- Test for common vulnerabilities (injection, XSS, etc.)
- Use parameterized queries and input validation

## 📋 Pull Request Process

### Before Submitting

- [ ] Code follows the style guidelines
- [ ] Tests have been added/updated
- [ ] Documentation has been updated
- [ ] All tests pass
- [ ] No merge conflicts

### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
Add screenshots to help explain your changes.

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Related Issues
Closes #(issue number)
```

## 🌟 Recognition

Contributors will be recognized in:

- README.md contributors section
- Release notes for significant contributions
- Special contributor badges
- Annual contributor spotlight

## 📞 Getting Help

- **Documentation**: Check the [Wiki](https://github.com/yourusername/IP_Ports_Scanner/wiki)
- **Discussions**: Use [GitHub Discussions](https://github.com/yourusername/IP_Ports_Scanner/discussions) for questions
- **Discord**: Join our [Discord server](https://discord.gg/yourserver) for real-time chat
- **Email**: Contact [contribute@yourdomain.com](mailto:contribute@yourdomain.com) for specific questions

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- The use of sexualized language or imagery and unwelcome sexual attention or advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

### Enforcement

Project maintainers are responsible for clarifying standards of acceptable behavior and are expected to take appropriate and fair corrective action in response to any instances of unacceptable behavior.

Report any incidents to [conduct@yourdomain.com](mailto:conduct@yourdomain.com).

---

Thank you for contributing to IP Ports Scanner! 🚀
