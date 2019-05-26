import sys, os
import uuid, lzma
import json
from UefiPi import allSectTypes, getSectTypeName

def RawGuid2Uuid(rawGuidBytes):
  return uuid.UUID(bytes=rawGuidBytes[3::-1] + rawGuidBytes[5:3:-1] + \
                         rawGuidBytes[7:5:-1] + rawGuidBytes[8:10] + rawGuidBytes[10:16])

def RawBytes2Readable(rawBytes):
  return hex(int(rawBytes[::-1].hex(), 16))

def RawBytes2Hex(rawBytes):
  return int(rawBytes[::-1].hex(), 16)

def ParseEfiSect(efiSectBytes, sectDict):
  end = 0
  sectCntDict = {}
  while end < len(efiSectBytes):
    sectSize, sectType = efiSectBytes[end:end+3], efiSectBytes[end+3:end+4]

    end += 4
    sectLen, hdrLen = RawBytes2Hex(sectSize), len(sectSize) + len(sectType)

    if RawBytes2Hex(sectType) not in allSectTypes():
      break

    sectName = getSectTypeName(RawBytes2Hex(sectType))
    if sectName not in sectCntDict:
      sectCntDict.update({sectName: 1})
    else:
      sectCntDict[sectName] += 1
      sectName = sectName + '_' + str(sectCntDict[sectName])

    sectDict.update({sectName: {'Size': RawBytes2Readable(sectSize), \
                                'Type': RawBytes2Readable(sectType)}})

    if RawBytes2Hex(sectSize) == 0xffffff:
      #EFI_COMMON_SECTION_HEADER2
      sectExtSize = efiSectBytes[end:end+4]
      end += 4
      sectLen, hdrLen = RawBytes2Hex(sectExtSize), len(sectSize)+len(sectType)+len(sectExtSize)
      sectDict[sectName].update({'ExtendedSize': RawBytes2Readable(sectExtSize)})

    if RawBytes2Hex(sectType) == 0x2:
      # EFI_SECTION_GUID_DEFINED
      print('found EFI_SECTION_GUID_DEFINED')
      sectDefGuid, dataOffset, sgdAttr = efiSectBytes[end:end+16], efiSectBytes[end+16:end+16+2], efiSectBytes[end+16+2:end+16+2+2]
      end += (16 + 2 + 2)
      if (RawGuid2Uuid(sectDefGuid) == uuid.UUID('{EE4E5898-3914-4259-9D6E-DC7BD79403CF}')):
        encap = efiSectBytes[end:end + sectLen - RawBytes2Hex(dataOffset)]
        end += (sectLen - RawBytes2Hex(dataOffset))
        print('Decapsulating encapsulations...')
        decap = lzma.decompress(encap)
        ParseEfiSect(decap, sectDict[sectName])

    elif RawBytes2Hex(sectType) == 0x17:
      #EFI_SECTION_FIRMWARE_VOLUME_IMAGE
      sectDict[sectName].update({'Fv': {}})
      ParseFvh(efiSectBytes[end:end+(sectLen - hdrLen)], sectDict[sectName]['Fv'])
      end += (sectLen - hdrLen)

    elif RawBytes2Hex(sectType) in allSectTypes():
      end += (sectLen - hdrLen)
    else:
      break
    
    for b in efiSectBytes[end:]:
      if b == 0x0:
        end += 1
      else:
        break

  return sectDict

def ParseFfs(ffsBytes, ffsDict):
  end, hdrLen = 0, 0
  ffsName, ffsIntegrityCheck, ffsFileType, ffsFileAttr, ffsFileSize, ffsFileState = \
    ffsBytes[end:end+16], ffsBytes[end+16:end+18], ffsBytes[end+18:end+19], ffsBytes[end+19:end+20], ffsBytes[end+20:end+23], ffsBytes[end+23:end+24]

  if not RawBytes2Hex(ffsFileAttr) & 0x40:
    # Check FFS_ATTRIB_CHECKSUM
    if not RawBytes2Hex(ffsIntegrityCheck[1:2]) == 0xaa:
      # Check EFI_FFS_INTEGRITY_CHECK
      return ffsDict

  end += 24
  hdrLen = 24
  ffsDict.update({'Name': str(RawGuid2Uuid(ffsName)),
                  'IntegrityCheck': ffsIntegrityCheck[::-1].hex(),
                  'Type': ffsFileType.hex(),
                  'Attributes': ffsFileAttr[::-1].hex(),
                  'Size': ffsFileSize[::-1].hex(),
                  'State': ffsFileState.hex()})

  # Check FFS_ATTRIB_LARGE_FILE
  if RawBytes2Hex(ffsFileAttr) & 0x01:
    # EFI_FFS_FILE_HEADER2
    ffsExtendedSize = ffsBytes[end:end+8]
    end += 8
    hdrLen += 8
    ffsDict.update({'ExtendedSize': RawBytes2Readable(ffsExtendedSize)})
  else:
    # EFI_FFS_FILE_HEADER
    pass

  efiSect = ffsBytes[end:end+RawBytes2Hex(ffsFileSize)-hdrLen]
  ffsDict.update(ParseEfiSect(efiSect, {}))
  end += (RawBytes2Hex(ffsFileSize) - hdrLen)

  return ffsDict


def ParseFvh(fvhBytes, fvhDict):
  if len(fvhBytes) == 0:
    return fvhDict

  ZeroVector, rawGuid, FvLength, Sig, Attribute, HeaderLength, Checksum, ExtHeaderOffset, Reserved, Revision = \
    fvhBytes[0:16], fvhBytes[16:32], fvhBytes[32:40], fvhBytes[40:44], fvhBytes[44:48], fvhBytes[48:50], fvhBytes[50:52], fvhBytes[52:54], fvhBytes[54:55], fvhBytes[55:56]

  end, FvBlockMap = 56, []

  while (len(FvBlockMap) == 0) or ((int(FvBlockMap[-1][0],16), int(FvBlockMap[-1][1],16)) != (0, 0)):
    NumBlocks, BlockLength = fvhBytes[end:end+4], fvhBytes[end+4:end+8]
    FvBlockMap.append((NumBlocks[::-1].hex(), BlockLength[::-1].hex()))
    end += 8

  fvhDict.update({'ZeroVector': ZeroVector[::-1].hex(), \
                  'Guid': str(RawGuid2Uuid(rawGuid)), \
                  'FvLength': RawBytes2Readable(FvLength), \
                  'Signature': str(Sig, 'utf-8'), \
                  'Attribute': Attribute[::-1].hex(), \
                  'HeaderLength': RawBytes2Readable(HeaderLength),
                  'Checksum': RawBytes2Readable(Checksum),
                  'ExtHeaderOffset': RawBytes2Readable(ExtHeaderOffset),
                  'Reserved': RawBytes2Readable(Reserved),
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
  if RawGuid2Uuid(rawGuid) == uuid.UUID('{5473C07A-3DCB-4dca-BD6F-1E9689E7349A}') or RawGuid2Uuid(rawGuid) == uuid.UUID('{8C8CE578-8A3D-4f1c-9935-896185C32DD3}'):
    # EFI_FIRMWARE_FILE_SYSTEM3_GUID or EFI_FIRMWARE_FILE_SYSTEM2_GUID
    ffsCnt, ffsDict = 0, {}
    while len(fvhBytes[end:]) != 0:
      ffsDict = ParseFfs(fvhBytes[end:], {})
      if not ffsDict:
        break

      fvhDict.update({'Ffs'+str(ffsCnt): ffsDict})

      # Check FFS_ATTRIB_LARGE_FILE
      if not int(fvhDict['Ffs'+str(ffsCnt)]['Attributes'], 16) & 0x01:
        end += int(fvhDict['Ffs'+str(ffsCnt)]['Size'], 16)
      else:
        end += int(fvhDict['Ffs'+str(ffsCnt)]['ExtendedSize'], 16)

      remainLen = len(fvhBytes[end:])
      remainFvh = fvhBytes[end:]
      for idx, b in enumerate(remainFvh):
        if b == 0xff:
          if not remainLen - idx < 0x18:
            if fvhBytes[end+18:end+19] == b'\xf0':
              if fvhBytes[end:end+16] == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff':
                # Check whether next FFS is EFI_FV_FILETYPE_FFS_PAD or not
                break
          end += 1
        else:
          break

      ffsCnt += 1

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
  
  with open ('Fv.json', 'w') as j:
    j.write(json.dumps(fvDict, indent = 4))