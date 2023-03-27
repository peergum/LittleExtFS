#include "LittleExtFS.h"

#include "filesystem.h"

LittleExtFS *LittleExtFS::_instance = 0;


LittleExtFS::LittleExtFS(SpiFlash *flash, size_t startBlock, size_t numBlocks, size_t blockSize) : 
    flash(flash), startBlock(startBlock), numBlocks(numBlocks), blockSize(blockSize) {
    _instance = this;
}

LittleExtFS::~LittleExtFS() {

}

int LittleExtFS::mount() {
    const auto fs = filesystem_get_instance(nullptr);

    int res = filesystem_mount(fs);

    return res;
}

int LittleExtFS::unmount() {
    const auto fs = filesystem_get_instance(nullptr);

    int res = filesystem_unmount(fs);

    return res;
}
