---
name: Bug Report
about: Create a report to help us improve
title: "[BUG] "
labels: "bug"
assignees: ""
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

Please provide detailed steps to reproduce the issue:

1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

A clear and concise description of what actually happened.

## Environment Details

Please provide the following information:

- **Home Assistant Version**: <!-- e.g., 2023.1.5 -->
- **Integration Version**: <!-- e.g., 1.0.0 -->
- **Device Model(s)**: <!-- e.g., GDSXXX -->
- **Device Firmware Version**: <!-- If known -->
- **Operating System**: <!-- e.g., HAOS, Docker, Windows, macOS -->
- **Browser**: <!-- if applicable -->
- **Installation Method**: <!-- HACS or Manual -->

## Logs

Please provide relevant logs from Home Assistant:

### Home Assistant Log

```
<-- Paste your Home Assistant logs here -->
```

### Integration Log

```
<-- Enable debug logging in configuration.yaml and paste logs here -->
logger:
  default: info
  logs:
    custom_components.grandstream_home: debug
```

## Additional Context

Add any other context about the problem here.

## Screenshots

If applicable, add screenshots to help explain your problem.

## Possible Solution

If you have any ideas on how to fix this, please describe them here.
