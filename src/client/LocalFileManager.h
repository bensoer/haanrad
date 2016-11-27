//
// Created by root on 26/11/16.
//

#ifndef HAANRAD_LOCALFILEMANAGER_H
#define HAANRAD_LOCALFILEMANAGER_H

#include <string>

class LocalFileManager {

private:

    std::string syncRootDir;

public:

    LocalFileManager(std::string syncRootDir);

    void buildOutDirectory(std::string haanradDir);

    void syncFile(std::string haanradDir, std::string rawData);

};


#endif //HAANRAD_LOCALFILEMANAGER_H
