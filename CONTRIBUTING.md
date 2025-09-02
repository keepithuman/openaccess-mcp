# Contributing to OpenAccess MCP

Thank you for your interest in contributing to OpenAccess MCP! This document provides guidelines and information for contributors.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** for your changes
4. **Make your changes** following our coding standards
5. **Test your changes** thoroughly
6. **Submit a pull request** with a clear description

## 🛠️ Development Setup

### Prerequisites

- Python 3.12+
- Git
- Docker (for testing)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/openaccess-mcp.git
cd openaccess-mcp

# Add upstream remote
git remote add upstream https://github.com/keepithuman/openaccess-mcp.git

# Install dependencies
make install-dev

# Generate audit keys for testing
make generate-keys

# Run tests to ensure everything works
make test
```

### Pre-commit Hooks

We use pre-commit hooks to ensure code quality:

```bash
# Install pre-commit hooks
pre-commit install

# Run manually if needed
pre-commit run --all-files
```

## 📝 Coding Standards

### Python Style

- **Formatting**: We use [Black](https://black.readthedocs.io/) and [Ruff](https://ruff.rs/)
- **Type Hints**: All functions should have type hints
- **Docstrings**: Use Google-style docstrings for all public functions
- **Line Length**: Maximum 100 characters

### Code Quality

```bash
# Format code
make format

# Lint code
make lint

# Run type checking
mypy openaccess_mcp/
```

### Testing

- **Coverage**: Aim for >90% test coverage
- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test complete workflows
- **Test Naming**: Use descriptive test names that explain the scenario

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/test_policy.py -v
```

## 🔒 Security Considerations

### Code Review Guidelines

- **Security Critical**: All changes are security-critical
- **Policy Engine**: Changes to policy logic require thorough review
- **Secret Handling**: Never log or expose secrets
- **Input Validation**: Validate all inputs, especially from MCP clients

### Security Checklist

- [ ] No secrets in logs or error messages
- [ ] Input validation for all user inputs
- [ ] Policy enforcement for all operations
- [ ] Audit logging for security-relevant actions
- [ ] No command injection vulnerabilities

## 🏗️ Architecture Guidelines

### Adding New Tools

1. **Define the schema** in the tool handler
2. **Implement policy checks** before execution
3. **Add audit logging** for all operations
4. **Handle errors gracefully** with proper error messages
5. **Add comprehensive tests**

Example tool structure:

```python
@self.server.tool("new.tool")
async def new_tool(
    profile_id: str,
    # ... other parameters
) -> Dict[str, Any]:
    """Execute a new tool operation."""
    try:
        # 1. Load profile and validate
        profile = await self._load_profile(profile_id)
        
        # 2. Resolve secrets
        secret = await self.secret_store.resolve(profile.auth)
        
        # 3. Enforce policy
        policy_context = PolicyContext(...)
        policy_decision = enforce_policy(policy_context)
        if not policy_decision.allowed:
            # Log and return error
            return ToolResult.error_result(...)
        
        # 4. Execute operation
        result = await self.provider.execute(...)
        
        # 5. Log success
        await self.audit_logger.log_tool_call(...)
        
        # 6. Return result
        return ToolResult.success_result(...)
        
    except Exception as e:
        # Log failure and return error
        return ToolResult.error_result(str(e))
```

### Adding New Providers

1. **Implement the interface** defined in the provider module
2. **Add proper error handling** and logging
3. **Include connection pooling** if applicable
4. **Add comprehensive tests** including error scenarios

## 🧪 Testing Guidelines

### Test Structure

```python
def test_feature_name():
    """Test description of what is being tested."""
    # Arrange
    # Set up test data and mocks
    
    # Act
    # Execute the function being tested
    
    # Assert
    # Verify the expected behavior
```

### Mocking

- **External Services**: Mock all external API calls
- **File System**: Use temporary files or mock file operations
- **Network**: Mock SSH connections and network calls
- **Time**: Mock time-dependent operations for deterministic tests

### Test Data

- **Fixtures**: Use pytest fixtures for common test data
- **Profiles**: Include test profiles with various policy configurations
- **Secrets**: Use mock secrets for testing (never real credentials)

## 📚 Documentation

### Code Documentation

- **Public APIs**: All public functions must have docstrings
- **Examples**: Include usage examples in docstrings
- **Type Hints**: Use comprehensive type hints
- **Error Cases**: Document possible error conditions

### User Documentation

- **README Updates**: Update README.md for new features
- **Examples**: Add examples to the examples/ directory
- **API Reference**: Document new tools and their parameters

## 🔄 Pull Request Process

### Before Submitting

1. **Ensure tests pass** locally
2. **Update documentation** if needed
3. **Check code quality** with linting tools
4. **Test with different configurations**

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Security Impact
- [ ] No security impact
- [ ] Security enhancement
- [ ] Security fix

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and quality checks
2. **Code Review**: At least one maintainer must approve
3. **Security Review**: Security-critical changes require additional review
4. **Merge**: Changes are merged after approval

## 🐛 Bug Reports

### Bug Report Template

```markdown
## Description
Clear description of the bug

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 20.04]
- Python Version: [e.g., 3.12.0]
- OpenAccess MCP Version: [e.g., 0.1.0]

## Additional Information
Logs, screenshots, etc.
```

## 💡 Feature Requests

### Feature Request Template

```markdown
## Problem Statement
Clear description of the problem being solved

## Proposed Solution
Description of the proposed solution

## Alternatives Considered
Other solutions that were considered

## Impact
- Security impact
- Performance impact
- User experience impact

## Implementation Notes
Any technical considerations or implementation details
```

## 🏷️ Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **Major**: Breaking changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Release notes written
- [ ] Security review completed

## 🤝 Community Guidelines

### Communication

- **Be Respectful**: Treat all contributors with respect
- **Be Constructive**: Provide constructive feedback
- **Be Patient**: Remember that contributors are volunteers
- **Be Inclusive**: Welcome contributors from all backgrounds

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Security Issues**: Email security@openaccess-mcp.dev

## 📄 License

By contributing to OpenAccess MCP, you agree that your contributions will be licensed under the Apache License 2.0.

## 🙏 Acknowledgments

Thank you for contributing to OpenAccess MCP! Your contributions help make remote access more secure and manageable for everyone.

---

**Questions?** Feel free to open an issue or start a discussion on GitHub!
