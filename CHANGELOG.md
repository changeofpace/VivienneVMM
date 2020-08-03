# Changelog

## [1.0.0] - 2020-08-02

VivienneVMM 1.0.0 released. :birthday:

### Added
- **Ept breakpoints**: a new breakpoint type with many advantages over the now deprecated Vivienne hardware breakpoint type.
- New VivienneCL commands: GetProcessInformation, QueryEptBpInfo, SetEptBpBasic, SetEptBpRegisters, SetEptBpKeyed, DisableEptBp, ClearEptBp, PrintEptBpLogHeader, and PrintEptBpLogElements. See the VivienneCL [README](./VivienneCL/README.md) for more information.
- Added extended information for many VivienneCL commands. Type 'help command_name' in the VivienneCL console to see a command's extended information.
- Most commands now have an abbreviated command name.

### Changed
- Rename the "breakpoint manager" to "hardware breakpoint manager".
- With the release of the second breakpoint manager, the project was refactored so that only one breakpoint manager can be active per project compilation. The ept breakpoint manager is the default breakpoint manager. Users can enable the legacy hardware breakpoint manager by modifying the [config header](.common/config.h).
- Changed the command name of many commands.
- Improved user and kernel debug routines.

### Deprecated
- The hardware breakpoint manager is now deprecated because it is susceptible to detection vectors.
