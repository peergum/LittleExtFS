#ifndef __LITTLEEXTFS_RK_H
#define __LITTLEEXTFS_RK_H

#include "SpiFlashRK.h"
#include "syscalls_posix.h"

class LittleExtFS {
 public:
  LittleExtFS(SpiFlash *flash, size_t startBlock, size_t numBlocks,
              size_t blockSize = 4096);
  virtual ~LittleExtFS();

  int mount();

  int unmount();

  size_t getStartBlock() const { return startBlock; };

  size_t getNumBlocks() const { return numBlocks; };

  size_t getBlockSize() const { return blockSize; };

  static SpiFlash *getFlashInstance() { return _instance->flash; };

  static LittleExtFS *getInstance() { return _instance; };

 protected:
  SpiFlash *flash;
  size_t startBlock = 0;
  size_t numBlocks = 0;
  size_t blockSize = 4096;
  static LittleExtFS *_instance;
};

#endif /* __LITTLEEXTFS_RK_H */
