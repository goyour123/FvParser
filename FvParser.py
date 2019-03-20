import sys, os

def RawGuid2Readable(rawGuidBytes):
  return rawGuid[3::-1].hex() + '-' + \
         rawGuid[5:3:-1].hex() + '-' + \
         rawGuid[7:5:-1].hex() + '-' + \
         rawGuid[8:10].hex() + '-' + rawGuid[10:16].hex()

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
                                         'FvLength': hex(int(FvLength[::-1].hex(), 16)), \
                                         'Signature': Sig, \
                                         'Attribute': Attribute[::-1].hex(), \
                                         'HeaderLength': hex(int(HeaderLength[::-1].hex(), 16)),
                                         'Checksum': hex(int(Checksum[::-1].hex(), 16)),
                                         'ExtHeaderOffset': hex(int(ExtHeaderOffset[::-1].hex(), 16)),
                                         'Reserved': Reserved,
                                         'Revision': hex(int(Revision.hex(), 16)),
                                         'FvBlockMap': FvBlockMap}})

        print('Fv Offset: ' + hex(blkOffset))
        print('ExtHeaderOffset: ' + ExtHeaderOffset[::-1].hex())

        # Check extended header
        if (int(ExtHeaderOffset[::-1].hex(), 16) != 0):
          f.seek(blkOffset + int(ExtHeaderOffset[::-1].hex(), 16))
          FvName, ExtHeaderSize = f.read(16), f.read(4)
          print(FvName, ExtHeaderSize)

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
  print(fvDict)
