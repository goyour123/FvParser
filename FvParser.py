import sys, os

if __name__ == '__main__':
  Signature, sigOffset = b'_FVH', 40
  fSize, blkSize = os.stat(sys.argv[1]).st_size, 0x1000
  fvDict = dict()
  with open(sys.argv[1], 'rb') as f:
    fvCnt = 0
    for blkOffset in range(0, fSize, blkSize):
      f.seek(blkOffset + sigOffset)
      data = f.read(len(Signature))
      FvBlockMap = []
      if data == Signature:
        fvCnt += 1
        print('Fv Offset: ' + hex(blkOffset))
        f.seek(blkOffset)
        ZeroVector, Guid, FvLength, Sig, Attribute, HeaderLength, Checksum, ExtHeaderOffset, Reserved, Revision = \
          f.read(16), f.read(16), f.read(8), f.read(4), f.read(4), f.read(2), f.read(2), f.read(2), f.read(1), f.read(1)

        while (len(FvBlockMap) == 0) or ((int(FvBlockMap[-1][0],16), int(FvBlockMap[-1][1],16)) != (0, 0)):
          NumBlocks, BlockLength = f.read(4), f.read(4)
          FvBlockMap.append((NumBlocks[::-1].hex(), BlockLength[::-1].hex()))

        # Update FV Header to dict
        fvDict.update({'Fv'+str(fvCnt): {'ZeroVector': ZeroVector, \
                                         'Guid': Guid, \
                                         'FvLength': FvLength, \
                                         'Signature': Sig, \
                                         'Attribute': Attribute, \
                                         'HeaderLength': HeaderLength,
                                         'Checksum': Checksum,
                                         'ExtHeaderOffset': ExtHeaderOffset,
                                         'Reserved': Reserved,
                                         'Revision': Revision,
                                         'FvBlockMap': FvBlockMap}})

        # Save FVs to file
        # f.seek(blkOffset)
        # fv = f.read(int(FvLength[::-1].hex(), 16))
        # fvName = 'Fv_' + str(hex(blkOffset)) + '.fv'
        # with open(fvName, 'wb') as fvFile:
        #   fvFile.write(fv)
  print(fvDict)
