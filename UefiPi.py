
EFI_SECTION_TYPE = {
    'EFI_SECTION_COMPRESSION': 0x01,
    'EFI_SECTION_GUID_DEFINED': 0x02,
    'EFI_SECTION_DISPOSABLE': 0x03,
    'EFI_SECTION_PE32': 0x10,
    'EFI_SECTION_PIC': 0x11,
    'EFI_SECTION_TE': 0x12,
    'EFI_SECTION_DXE_DEPEX': 0x13,
    'EFI_SECTION_VERSION': 0x14,
    'EFI_SECTION_USER_INTERFACE': 0x15,
    'EFI_SECTION_COMPATIBILITY16': 0x16,
    'EFI_SECTION_FIRMWARE_VOLUME_IMAGE': 0x17,
    'EFI_SECTION_FREEFORM_SUBTYPE_GUID': 0x18,
    'EFI_SECTION_RAW': 0x19,
    'EFI_SECTION_PEI_DEPEX': 0x1B,
    'EFI_SECTION_MM_DEPEX': 0x1C,
}

def allSectTypes():
    return EFI_SECTION_TYPE.values()

def getSectTypeName(sectType):
    if sectType not in EFI_SECTION_TYPE.values():
        return None
    for k, v in EFI_SECTION_TYPE.items():
        if v == sectType:
            return k
