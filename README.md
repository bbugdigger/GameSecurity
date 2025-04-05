This repository is a collection of techniques related to game security and I believe would be usefull for a anti-cheat to have.

**Note**: Drivers that are built should be loaded with kdmapper or by exploiting some other vulnerable driver since my drivers are not signed.

### Collection

- **HandleMonitor** -> strips access rights to processes that are opening/duplicating game handle
- **Driver Blocker** *(work in progress)* -> after this driver is loaded it will block loading other drivers until reboot
  - I think this is a nice feature for anti-cheats to have however not so easy to implement.
  - The reason this is a little tricky is because driver mappers (like kdmapper) will abuse vulnerable driver to load their own, therefore they wont be loading driver using WIN API
  - Ideas I have tried so far:
    - `PsSetLoadImageNotifyRoutine` callback, the problem with this implementation is the callback runs after the image is already loaded and mapped into memory. By this point, the driver has already been loaded into kernel space so only thing left to do at this point is just patch the entry point maybe?
    - `ObRegisterCallbacks` (using `ObjectType == *IoDriverObjectType`) or hooking `NtLoadDriver` but if cheat driver is being loaded by the vulnerable driver the `PDRIVER_OBJECT DriverObject` wont even get created so these wont have any effect
