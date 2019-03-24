import sys, os

def RawGuid2Readable(rawGuidBytes):
  return rawGuidBytes[3::-1].hex() + '-' + \
         rawGuidBytes[5:3:-1].hex() + '-' + \
         rawGuidBytes[7:5:-1].hex() + '-' + \
         rawGuidBytes[8:10].hex() + '-' + rawGuidBytes[10:16].hex()

def RawBytes2Readable(rawBytes):
  return hex(int(rawBytes[::-1].hex(), 16))

def RawBytes2Hex(rawBytes):
  return int(rawBytes[::-1].hex(), 16)

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
                                         'Guid': RawGuid2Readable(rawGuid), \
                                         'FvLength': RawBytes2Readable(FvLength), \
                                         'Signature': Sig, \
                                         'Attribute': Attribute[::-1].hex(), \
                                         'HeaderLength': RawBytes2Readable(HeaderLength),
                                         'Checksum': RawBytes2Readable(Checksum),
                                         'ExtHeaderOffset': RawBytes2Readable(ExtHeaderOffset),
                                         'Reserved': Reserved,
                                         'Revision': RawBytes2Readable(Revision),
                                         'FvBlockMap': FvBlockMap}})

        print('Fv Offset: ' + hex(blkOffset))

        # Check extended header
        if (int(ExtHeaderOffset[::-1].hex(), 16) != 0):
          f.seek(blkOffset + int(ExtHeaderOffset[::-1].hex(), 16))
          FvName, ExtHeaderSize = f.read(16), f.read(4)
          fvDict['Fv'+str(fvCnt)].update({'ExtFvName': RawGuid2Readable(FvName), \
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

        # Save FVs to file
        try:
          sys.argv[2]
        except:
          pass
        else:
          if sys.argv[2] == '-s':
            f.seek(blkOffset)
            fv = f.read(int(FvLength[::-1].hex(), 16))
            fvName = binName+ '_' + str(hex(blkOffset)) + '.fv'
            with open(fvName, 'wb') as fvFile:
              fvFile.write(fv)
  for i in fvDict:
    print(fvDict[i])
