# Changelog

## [1.0.0] - 2020-08-02

VivienneVMM 1.0.0 released. :birthday:

### Added
- **Ept breakpoints**: a new breakpoint type with many advantages over the now deprecated Vivienne hardware breakpoint type.
- New VivienneCL commands: GetProcessInformation, QueryEptBpInfo, SetEptBpBasic, SetEptBpRegisters, SetEptBpKeyed, DisableEptBp, ClearEptBp, PrintEptBpLogHeader, and PrintEptBpLogElements. See the VivienneCL [README](./VivienneCL/README.md) for more information.
- Add extended information for many VivienneCL commands. Type 'help command_name' in the VivienneCL console to see a command's extended information.
- Most VivienneCL commands now have an additional short name for ease of use.
- New config options: CFG_VIVIENNE_DEVICE_NAME, CFG_LOG_NUMBER_OF_PAGES, CFG_LOG_FLUSH_INTERVAL_MS, and CFG_LOG_APPEND_DATA_TO_EXISTING_LOG_FILE. See the [config header](./common/config.h) for more information.
- Add a [CHANGELOG](./CHANGELOG.md) file.

### Changed
- Rename the "breakpoint manager" module to "hardware breakpoint manager".
- With the release of the second breakpoint manager, the project was refactored so that only one breakpoint manager can be active per project compilation. The ept breakpoint manager is the default breakpoint manager. Users can enable the legacy hardware breakpoint manager by modifying the [config header](.common/config.h).
- Changed the command name of many commands.
- Improved user and kernel debug routines.
- Removed the CFG_DELETE_EXISTING_LOGFILE config option.

### Deprecated
- The hardware breakpoint manager is now deprecated because it is susceptible to detection vectors.
