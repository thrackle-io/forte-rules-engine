# Gas Reports Directory

This directory contains gas usage reports for the Rules Engine project.

## Files

- **`GAS_USAGE.md`** - The main gas usage report, updated with every local run and CI build
- **`archive/`** - Directory containing timestamped archive files created on every merge to main
  - **`gas-report_YYYYMMDD_HHMMSS_<commit>.md`** - Timestamped historical reports

## Usage

### Local Development
Run the gas report script to update the main report:
```bash
./script/reportGas.sh
```

This will update `gasReports/GAS_USAGE.md` with the latest gas measurements.

### CI/CD
On every merge to main, the GitHub Actions workflow:
1. Updates `gasReports/GAS_USAGE.md` with latest data
2. Creates a timestamped archive copy in `gasReports/archive/` for historical tracking
3. Commits both files back to the repository

## Historical Tracking

Archive files in the `archive/` directory allow you to track gas usage changes over time:
- Compare current vs previous reports
- Identify performance regressions
- Track optimization improvements
- Maintain audit trail of gas usage evolution

## Directory Structure

```
gasReports/
├── GAS_REPORTS.md          # This documentation file
├── GAS_USAGE.md            # Current gas usage report (always latest)
└── archive/                # Historical archive directory
    ├── gas-report_20241210_143052_abc123f.md
    ├── gas-report_20241210_150032_def456a.md
    └── ...                 # Additional timestamped reports
```