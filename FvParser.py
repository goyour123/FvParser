import sys, os
import uuid, lzma

def RawGuid2Uuid(rawGuidBytes):
  return uuid.UUID(bytes=rawGuidBytes[3::-1] + rawGuidBytes[5:3:-1] + \
                         rawGuidBytes[7:5:-1] + rawGuidBytes[8:10] + rawGuidBytes[10:16])

def RawBytes2Readable(rawBytes):
  return hex(int(rawBytes[::-1].hex(), 16))

def RawBytes2Hex(rawBytes):
  return int(rawBytes[::-1].hex(), 16)

def ParseEfiSect(efiSectBytes, sectDict):

  if len(efiSectBytes) == 0:
    return sectDict

  sectSize, sectType = efiSectBytes[0:3], efiSectBytes[3:4]
  end = 4
  sectLen, hdrLen = RawBytes2Hex(sectSize), len(sectSize) + len(sectType)

  if RawBytes2Hex(sectType) == 0xff:
    return sectDict

  sectDict.update({RawBytes2Readable(sectType): {'Size': RawBytes2Readable(sectSize), \
                                                 'Type': RawBytes2Readable(sectType)}})

  if RawBytes2Hex(sectSize) == 0xffffff:
    #EFI_COMMON_SECTION_HEADER2
    sectExtSize = efiSectBytes[end:end+4]
    end += 4
    sectLen, hdrLen = RawBytes2Hex(sectExtSize), len(sectSize)+len(sectType)+len(sectExtSize)
    sectDict[RawBytes2Readable(sectType)].update({'ExtendedSize': RawBytes2Readable(sectExtSize)})

  if RawBytes2Hex(sectType) == 0x2:
    #EFI_SECTION_GUID_DEFINED
    sectDefGuid, dataOffset, sgdAttr = efiSectBytes[end:end+16], efiSectBytes[end+16:end+16+2], efiSectBytes[end+16+2:end+16+2+2]
    end += (16 + 2 + 2)
    if (RawGuid2Uuid(sectDefGuid) == uuid.UUID('{EE4E5898-3914-4259-9D6E-DC7BD79403CF}')):
      encap = efiSectBytes[end:end + sectLen - RawBytes2Hex(dataOffset)]
      end += (sectLen - RawBytes2Hex(dataOffset))
      print('Decapsulating encapsulations...')
      decap = lzma.decompress(encap)
      ParseEfiSect(decap, sectDict[RawBytes2Readable(sectType)])

  elif RawBytes2Hex(sectType) == 0x17:
    #EFI_SECTION_FIRMWARE_VOLUME_IMAGE
    sectDict[RawBytes2Readable(sectType)].update({'Fv': {}})
    ParseFvh(efiSectBytes[end:end+(sectLen - hdrLen)], sectDict[RawBytes2Readable(sectType)]['Fv'])
    end += (sectLen - hdrLen)

  elif RawBytes2Hex(sectType) == 0x19:
    #EFI_SECTION_RAW
    end += (sectLen - hdrLen)

  else:
    end += (sectLen - hdrLen)

  return ParseEfiSect(efiSectBytes[end::], sectDict)

def ParseFvh(fvhBytes, fvhDict):  
  if len(fvhBytes) == 0:
    return fvhDict

  ZeroVector, rawGuid, FvLength, Sig, Attribute, HeaderLength, Checksum, ExtHeaderOffset, Reserved, Revision = \
    fvhBytes[0:16], fvhBytes[16:32], fvhBytes[32:40], fvhBytes[40:44], fvhBytes[44:48], fvhBytes[48:50], fvhBytes[50:52], fvhBytes[52:54], fvhBytes[54:55], fvhBytes[55:56]
  
  end, FvBlockMap= 56, []

  while (len(FvBlockMap) == 0) or ((int(FvBlockMap[-1][0],16), int(FvBlockMap[-1][1],16)) != (0, 0)):
    NumBlocks, BlockLength = fvhBytes[end:end+4], fvhBytes[end+4:end+8]
    FvBlockMap.append((NumBlocks[::-1].hex(), BlockLength[::-1].hex()))
    end += 8

  fvhDict.update({'ZeroVector': ZeroVector, \
                  'Guid': str(RawGuid2Uuid(rawGuid)), \
                  'FvLength': RawBytes2Readable(FvLength), \
                  'Signature': Sig, \
                  'Attribute': Attribute[::-1].hex(), \
                  'HeaderLength': RawBytes2Readable(HeaderLength),
                  'Checksum': RawBytes2Readable(Checksum),
                  'ExtHeaderOffset': RawBytes2Readable(ExtHeaderOffset),
                  'Reserved': Reserved,
                  'Revision': RawBytes2Readable(Revision),
                  'FvBlockMap': FvBlockMap})

  # Check extended header
  if (RawBytes2Hex(ExtHeaderOffset) != 0x0):
    end = RawBytes2Hex(ExtHeaderOffset)
    FvName, ExtHeaderSize = fvhBytes[end:end+16], fvhBytes[end+16:end+20]
    end += 20
    fvhDict.update({'ExtFvName': str(RawGuid2Uuid(FvName)), \
                    'ExtHeaderSize': RawBytes2Readable(ExtHeaderSize)})

    ExtEntrySize, ExtEntryType = fvhBytes[end:end+2], fvhBytes[end+2:end+4]
    end += 4
    if RawBytes2Hex(ExtEntryType) == 0x1:
      # EFI_FV_EXT_TYPE_OEM_TYPE
      pass
    elif RawBytes2Hex(ExtEntryType) == 0x2:
      # EFI_FV_EXT_TYPE_GUID_TYPE
      pass
    elif RawBytes2Hex(ExtEntryType) == 0x3:
      # EFI_FV_EXT_TYPE_USED_SIZE_TYPE
      pass
    elif RawBytes2Hex(ExtEntryType) == 0xffff:
      fvhDict.update({'ExtEntrySize': RawBytes2Readable(ExtEntrySize), \
                      'ExtEntryType': RawBytes2Readable(ExtEntryType)})
    else:
      pass

  # Check EFI_FFS_FILE_HEADER
  if (RawGuid2Uuid(rawGuid) == uuid.UUID('{5473C07A-3DCB-4dca-BD6F-1E9689E7349A}')):
    # EFI_FIRMWARE_FILE_SYSTEM3_GUID
    ffsName, ffsIntegrityCheck, ffsFileType, ffsFileAttr, ffsFileSize, ffsFileState = \
      fvhBytes[end:end+16], fvhBytes[end+16:end+18], fvhBytes[end+18:end+19], fvhBytes[end+19:end+20], fvhBytes[end+20:end+23], fvhBytes[end+23:end+24]
    end += 24
    fvhDict.update({'Ffs': {'Name': str(RawGuid2Uuid(ffsName)),
                            'IntegrityCheck': ffsIntegrityCheck[::-1].hex(),
                            'Type': ffsFileType.hex(),
                            'Attributes': ffsFileAttr[::-1].hex(),
                            'Size': ffsFileSize[::-1].hex(),
                            'State': ffsFileState.hex()}})
    # Check FFS_ATTRIB_LARGE_FILE
    if RawBytes2Hex(ffsFileAttr) & 0x01:
      # EFI_FFS_FILE_HEADER2
      ffsExtendedSize = fvhBytes[end:end+8]
      end += 8
      fvhDict['Fv'+str(fvCnt)]['Ffs'].update({'ExtendedSize': RawBytes2Readable(ffsExtendedSize)})
    else:
      # EFI_FFS_FILE_HEADER
      pass

    efiSect = fvhBytes[end:end+RawBytes2Hex(ffsFileSize)]
    fvhDict['Ffs'].update(ParseEfiSect(efiSect, {}))

  return fvhDict


if __name__ == '__main__':
  Signature, sigOffset, lenOffset = b'_FVH', 40, 32
  fSize, blkSize = os.stat(sys.argv[1]).st_size, 0x1000
  fvDict = dict()
  with open(sys.argv[1], 'rb') as f:
    fvCnt = 0
    binName = os.path.splitext(os.path.basename(sys.argv[1]))[0]
    for blkOffset in range(0, fSize, blkSize):
      f.seek(blkOffset + sigOffset)
      data = f.read(len(Signature))
      FvBlockMap = []
      if data == Signature:
        print('Found Fv Offset: ' + hex(blkOffset))
        fvCnt += 1
        fvDict.update({'Fv'+str(fvCnt): {}})

        f.seek(blkOffset + lenOffset)
        length = RawBytes2Hex(f.read(8))

        f.seek(blkOffset)
        ParseFvh(f.read(length), fvDict['Fv'+str(fvCnt)])

        # Save FVs to file
        try:
          sys.argv[2]
        except:
          pass
        else:
          if sys.argv[2] == '-fv':
            f.seek(blkOffset)
            fv = f.read(int(FvLength[::-1].hex(), 16))
            fvName = binName+ '_' + str(hex(blkOffset)) + '.fv'
            with open(fvName, 'wb') as fvFile:
              fvFile.write(fv)
  for i in fvDict:
    print(fvDict[i])
