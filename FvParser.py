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

  elif RawBytes2Hex(sectType) == 0x19:
    end += (sectLen - hdrLen)

  else:
    end += (sectLen - hdrLen)

  return ParseEfiSect(efiSectBytes[end::], sectDict)

if __name__ == '__main__':
  Signature, sigOffset = b'_FVH', 40
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
        fvCnt += 1
        f.seek(blkOffset)
        ZeroVector, rawGuid, FvLength, Sig, Attribute, HeaderLength, Checksum, ExtHeaderOffset, Reserved, Revision = \
          f.read(16), f.read(16), f.read(8), f.read(4), f.read(4), f.read(2), f.read(2), f.read(2), f.read(1), f.read(1)

        while (len(FvBlockMap) == 0) or ((int(FvBlockMap[-1][0],16), int(FvBlockMap[-1][1],16)) != (0, 0)):
          NumBlocks, BlockLength = f.read(4), f.read(4)
          FvBlockMap.append((NumBlocks[::-1].hex(), BlockLength[::-1].hex()))

        # Update FV Header to dict
        fvDict.update({'Fv'+str(fvCnt): {'ZeroVector': ZeroVector, \
                                         'Guid': str(RawGuid2Uuid(rawGuid)), \
                                         'FvLength': RawBytes2Readable(FvLength), \
                                         'Signature': Sig, \
                                         'Attribute': Attribute[::-1].hex(), \
                                         'HeaderLength': RawBytes2Readable(HeaderLength),
                                         'Checksum': RawBytes2Readable(Checksum),
                                         'ExtHeaderOffset': RawBytes2Readable(ExtHeaderOffset),
                                         'Reserved': Reserved,
                                         'Revision': RawBytes2Readable(Revision),
                                         'FvBlockMap': FvBlockMap}})

        print('Found Fv Offset: ' + hex(blkOffset))

        # Check extended header
        if (int(ExtHeaderOffset[::-1].hex(), 16) != 0):
          f.seek(blkOffset + int(ExtHeaderOffset[::-1].hex(), 16))
          FvName, ExtHeaderSize = f.read(16), f.read(4)
          fvDict['Fv'+str(fvCnt)].update({'ExtFvName': str(RawGuid2Uuid(FvName)), \
                                          'ExtHeaderSize': RawBytes2Readable(ExtHeaderSize)})
          
          ExtEntrySize, ExtEntryType = f.read(2), f.read(2)
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
            fvDict['Fv'+str(fvCnt)].update({'ExtEntrySize': RawBytes2Readable(ExtEntrySize), \
                                            'ExtEntryType': RawBytes2Readable(ExtEntryType)})
          else:
            pass

        # Check EFI_FFS_FILE_HEADER
        if (RawGuid2Uuid(rawGuid) == uuid.UUID('{5473C07A-3DCB-4dca-BD6F-1E9689E7349A}')):
          # EFI_FIRMWARE_FILE_SYSTEM3_GUID
          ffsName, ffsIntegrityCheck, ffsFileType, ffsFileAttr, ffsFileSize, ffsFileState = \
            f.read(16), f.read(2), f.read(1), f.read(1), f.read(3), f.read(1)
          fvDict['Fv'+str(fvCnt)].update({'Ffs': {'Name': str(RawGuid2Uuid(ffsName)),
                                                  'IntegrityCheck': ffsIntegrityCheck[::-1].hex(),
                                                  'Type': ffsFileType.hex(),
                                                  'Attributes': ffsFileAttr[::-1].hex(),
                                                  'Size': ffsFileSize[::-1].hex(),
                                                  'State': ffsFileState.hex()}})
          # Check FFS_ATTRIB_LARGE_FILE
          if RawBytes2Hex(ffsFileAttr) & 0x01:
            # EFI_FFS_FILE_HEADER2
            ffsExtendedSize = f.read(8)
            fvDict['Fv'+str(fvCnt)]['Ffs'].update({'ExtendedSize': RawBytes2Readable(ffsExtendedSize)})
          else:
            # EFI_FFS_FILE_HEADER
            pass

          efiSect = f.read(RawBytes2Hex(ffsFileSize))
          fvDict['Fv'+str(fvCnt)]['Ffs'].update(ParseEfiSect(efiSect, {}))

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
