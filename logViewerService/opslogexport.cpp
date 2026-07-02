// SPDX-FileCopyrightText: 2025 - 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "opslogexport.h"
#include "opslogpaths.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <QProcess>
#include <QString>
#include <QStringList>
#include <QFile>
#include <QDebug>
#include <QBuffer>
#include <QDirIterator>
#include <QFileInfo>
#include <QDir>

using namespace std;

static void appendToFile(const QString &filePath, const QByteArray &content)
{
    QFile file(filePath);

    if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        file.write(content);
    } else {
        qWarning() << "Error opening file for writing:" << file.errorString();
    }
}

/**
 * @brief 在 QByteArray 数据中查找包含指定模式的行，并返回该行及其后面的N行。
 *        功能类似于 `grep -A N pattern`，但操作的是内存中的数据。
 *
 * @param data     包含文本数据的 QByteArray。
 * @param pattern  要搜索的字符串模式。
 * @param afterLines 匹配成功后，要额外包含的后续行数 (N)。
 * @return QList<QStringList> 每个 QStringList 代表一个匹配块。
 */
QList<QStringList> grepA(const QByteArray &data, const QString &pattern, int afterLines)
{
    QList<QStringList> allMatches;

    // 使用 QBuffer 将 QByteArray 包装成一个 QIODevice
    QBuffer buffer;
    buffer.setData(data);
    if (!buffer.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "Cannot open QBuffer for reading.";
        return allMatches;
    }

    // QTextStream 可以直接从任何 QIODevice 读取数据
    QTextStream in(&buffer);
    // 假设数据是 UTF-8 编码，如果不是，需要设置正确的 codec
    // in.setCodec("UTF-8");

    while (!in.atEnd()) {
        QString line = in.readLine();

        // 检查当前行是否包含目标模式
        if (line.contains(pattern)) {
            QStringList currentMatchGroup;
            currentMatchGroup.append(line); // 添加匹配到的行

            // 读取并添加后续的 'afterLines' 行
            for (int i = 0; i < afterLines && !in.atEnd(); ++i) {
                currentMatchGroup.append(in.readLine());
            }

            // 将这个匹配块添加到总的结果列表中
            allMatches.append(currentMatchGroup);
        }
    }

    return allMatches;
}

static void appendToFileWithGrepA(const QString &filePath, const QByteArray &content, const QString &pattern, int afterLines)
{
    QList<QStringList> matches = grepA(content, pattern, afterLines);

    if (matches.isEmpty()) {
        appendToFile(filePath, {});
    } else {
        QFile file(filePath);

        if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            bool firstGroup = true;
            for (const QStringList &group : matches) {
                if (!firstGroup) {
                    file.write("--\n");
                }
                for (const QString &line : group) {
                    file.write(line.toLocal8Bit());
                    file.write("\n");
                }
                firstGroup = false;
            }
        } else {
            qWarning() << "Error opening file for writing:" << file.errorString();
        }
    }
}

static int runProcess(const QStringList &args, const char *outputFile = nullptr, const QString &pattern = "", int afterLines = -1)
{
    if (args.isEmpty()) {
        qWarning() << "runProcess: args is empty";
        return -1;
    }
    qDebug() << "runProcess" << args;

    QProcess proc;
    proc.setProgram(args.at(0));
    proc.setArguments(args.mid(1));
    proc.start(QIODevice::ReadWrite);
    proc.waitForFinished(-1);

    int exitcode = proc.exitCode();
    if (outputFile) {
        if (pattern != "" && afterLines >= 0) {
            appendToFileWithGrepA(outputFile, proc.readAllStandardOutput(), pattern, afterLines);
        } else {
            appendToFile(outputFile, proc.readAllStandardOutput());
        }
    }
    qDebug() << "runProcess exitcode:" << exitcode << proc.errorString();
    return exitcode;
}

static QStringList expandPathWithWildcardIterator(const QString &pathWithWildcard)
{
    // 1. 分离目录和文件名模式
    QFileInfo fileInfo(pathWithWildcard);
    QString dirPath = fileInfo.path();
    QString fileNamePattern = fileInfo.fileName();

    QStringList matchedFiles;
    QStringList nameFilters;
    nameFilters << fileNamePattern;

    // 2. 创建 QDirIterator
    // 构造函数参数：目录, 名称过滤器, 实体类型过滤器, 迭代器标志
    QDirIterator it(dirPath, nameFilters, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::NoIteratorFlags);

    // 3. 循环遍历所有匹配项
    while (it.hasNext()) {
        // it.next() 直接返回下一个匹配项的完整路径
        matchedFiles.append(it.next());
    }

    return matchedFiles;
}

OpsLogExport::OpsLogExport(const string &target, uint callerUid, uint callerGid)
    : target_dir(target)
    , m_callerUid(callerUid)
    , m_callerGid(callerGid)
{
}

void OpsLogExport::run()
{
    // 安全加固：在执行任何拷贝操作前，验证目标目录路径安全（无符号链接、在 /var/log 下）
    if (!ensureSafeTargetDir()) {
        qWarning() << "OpsLogExport::run: target directory safety check failed, aborting export";
        return;
    }

    createOpsLogDirStruct(QString::fromStdString(target_dir));

    exportAppLogs();
    exportSystemLogs();
    exportKernelLogs();
    exportDDELogs();
    exportHWLogs();
    exportOSVersionLogs();
    exportAdditionalLogs();
    exportAptLogs();
    exportUosSteLogs();
    exportUosSteTwoLogs();

    // 递归设置目录及文件的权限
    setDirectoryPermissionsSafe(target_dir);
}

void OpsLogExport::createOpsLogDirStruct(const QString &outDir)
{
    // 创建目录结构
    QStringList dirs = {
        outDir + QString(kKernelPath),
        outDir + QString(kSystemPath),
        outDir + QString(kDDEPath),
        outDir + QString(kAppPath),
        outDir + QString(kJournalPath),
        outDir + QString(kAptPath),
        outDir + QString(kUosStePath),
        outDir + QString(kUossteLogsPath),
        outDir + QString(kDefenderPath),
        outDir + QString(kCloudPrintPath),
        outDir + QString(kCloudScanPath),
        outDir + QString(kPrinterPath),
        outDir + QString(kGraphicsDriverManagerPath),
        outDir + QString(kBootMakerPath),
        outDir + QString(kScanerPath),
        outDir + QString(kKMSPath),
        outDir + QString(kCompressorPath),
        outDir + QString(kCalendarPath),
        outDir + QString(kManualPath),
        outDir + QString(kReaderPath),
        outDir + QString(kFontManagerPath),
        outDir + QString(kDebInstallerPath),
        outDir + QString(kTerminalPath),
        outDir + QString(kVoiceNotPath),
        outDir + QString(kDevicemanagerPath),
        outDir + QString(kServiceSupportPath),
        outDir + QString(kRemoteAssistancePath),
        outDir + QString(kSystemMonitorPath),
        outDir + QString(kEditorPath),
        outDir + QString(kCalculatorPath),
        outDir + QString(kMailPath),
        outDir + QString(kScreenRecorderPath),
        outDir + QString(kDrawPath),
        outDir + QString(kMusicPath),
        outDir + QString(kImageViewerPath),
        outDir + QString(kAlbumPath),
        outDir + QString(kMoviePath),
        outDir + QString(kCameraPath),
        outDir + QString(kChineseImePath),
        outDir + QString(kDeepinInstallerPath),
        outDir + QString(kDeepinRecoveryPath),
        outDir + QString(kOemCustomPath),
        outDir + QString(kUosActivatorPath),
        outDir + QString(kUosActivatorLogPath),
        outDir + QString(kFcitxPath),
        outDir + QString(kDiskManagerPath),
        outDir + QString(kDownloaderPath),
        outDir + QString(kKwinPath),
        outDir + QString(kKboxPath),
        outDir + QString(kDeepinLogViewerPath),
        outDir + QString(kDdeDesktopPath),
        outDir + QString(kDdeFileManagerPath),
        outDir + QString(kDdeDockPath),
        outDir + QString(kSystemPulseaudioPath)
    };

    // hisi目录仅在源目录存在时创建
    if (path_exists("/var/log/hisi")) {
        dirs.push_back(outDir + QString(kHisiPath));
    }

    for (const QString &dir : dirs) {
        QDir(dir).mkpath(".");
    }
}

bool OpsLogExport::path_exists(const string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

/*!
 * \brief 验证目标目录在 /var/log 下。
 *
 * target_dir 由 LogViewerService::exportOpsLog() 通过 QTemporaryDir 在 /var/log 下
 * 随机创建（root 控制、用户不可预测路径），此处仅做防御性前缀校验。
 *
 * \return true 表示路径在 /var/log 下；false 表示路径异常。
 */
bool OpsLogExport::ensureSafeTargetDir()
{
    const QString canonicalTarget = QDir::cleanPath(QString::fromStdString(target_dir));
    const QString kVarLogPrefix = "/var/log";
    if (!canonicalTarget.startsWith(kVarLogPrefix + "/")) {
        qWarning() << "ensureSafeTargetDir: target_dir is not under /var/log:" << canonicalTarget;
        return false;
    }
    return true;
}
void OpsLogExport::copy_file_or_dir(const string &src, const string &dst_dir)
{
    if (!path_exists(src)) return;

    QString qSrc = QString::fromStdString(src);
    QString qDst = QString::fromStdString(dst_dir);

    QFileInfo srcInfo(qSrc);
    if (srcInfo.isFile()) {
        // 单个文件：确保目标目录存在后用 QFile::copy
        QDir().mkpath(qDst);
        QString dstFile = qDst + "/" + srcInfo.fileName();
        QFile::remove(dstFile);  // QFile::copy 要求目标不存在
        QFile::copy(qSrc, dstFile);
    } else {
        // 目录：递归复制，-P 不跟随符号链接（复制链接本身而非目标内容）
        runProcess({"cp", "-rP", qSrc, qDst});
    }
}

void OpsLogExport::execute_command(const QStringList &args, const string &output_file)
{
    runProcess(args, output_file.c_str());
}

void OpsLogExport::setDirectoryPermissionsSafe(const string &dir_path)
{
    // 基本校验：确认路径在 /var/log 下。目录由 root 通过 QTemporaryDir 在 /var/log 下
    // 随机创建（mkdtemp，初始 0700，路径用户不可预测），故 chown 其内容给 caller 是安全的——
    // 不会重新引入旧设计中 root 写入用户家目录的符号链接攻击面。
    const QString canonicalDir = QDir::cleanPath(QString::fromStdString(dir_path));
    const QString kVarLogPrefix = "/var/log";
    if (!canonicalDir.startsWith(kVarLogPrefix + "/")) {
        qWarning() << "setDirectoryPermissionsSafe: dir_path is not under /var/log, refusing:" << canonicalDir;
        return;
    }

    // 收缩到最小权限：目录 0700、文件 0600，并 chown 给调用 DBus 的前端用户。
    // 仅 caller 能读取 root 收集的系统日志，避免 0755/0644 时任意本地用户在
    // exportOpsLog 返回至前端拷贝完成的时间窗内读取 auth.log/syslog 等敏感日志。
    //
    // 仍需递归处理：copy_file_or_dir() 对目录用 `cp -rP` 会保留源目录 mode（如
    // /var/log/journal 常为 0700/02755），必须统一刷成 0700/0600 并交给 caller。
    const QFile::Permissions dirPerms = QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
    const QFile::Permissions filePerms = QFile::ReadOwner | QFile::WriteOwner;

    const uid_t callerUid = static_cast<uid_t>(m_callerUid);
    const gid_t callerGid = static_cast<gid_t>(m_callerGid);

    auto applySafeOwnership = [&](const QString &path, bool isDir) {
        if (::chown(QFile::encodeName(path).constData(), callerUid, callerGid) != 0) {
            qWarning() << "Failed to chown export path:" << path << "error:" << strerror(errno);
            return;
        }
        QFile::setPermissions(path, isDir ? dirPerms : filePerms);
    };

    // 顶层临时目录本身（QTemporaryDir 经 mkdtemp 创建，非符号链接）
    applySafeOwnership(canonicalDir, true);

    // QDirIterator 默认不跟随符号链接（NoIteratorFlags）
    QDirIterator it(canonicalDir, QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        const QFileInfo &info = it.fileInfo();
        if (info.isSymLink())
            continue;  // 跳过符号链接，不修改其属主与权限
        applySafeOwnership(info.filePath(), info.isDir());
    }
}

void OpsLogExport::exportAppLogs()
{
    // 云打印
    copy_file_or_dir("/var/log/cups/dcp_log", target_dir + "/app/deepin-cloud-print/");
    // 打印管理器
    copy_file_or_dir("/var/log/cups/error_log", target_dir + "/app/dde-printer/");
    // 显卡驱动管理器
    copy_file_or_dir("/var/log/deepin-graphics-driver-manager-server.log", target_dir + "/app/deepin-graphics-driver-manager/");
    // 启动盘制作工具
    copy_file_or_dir("/var/log/deepin/deepin-boot-maker-service.log", target_dir + "/app/deepin-boot-maker/");
    // 安装器
    copy_file_or_dir("/var/log/deepin-installer.log", target_dir + "/app/deepin-installer/");
    copy_file_or_dir("/var/log/deepin-installer-first-boot.log", target_dir + "/app/deepin-installer/");
    // 备份还原
    copy_file_or_dir("/recovery/deepin-recovery-gui.log", target_dir + "/app/deepin-recovery/");
    copy_file_or_dir("/recovery/deepin-recovery-gui-old.log", target_dir + "/app/deepin-recovery/");
    // ISO定制工具
    copy_file_or_dir("/var/local/oem-custom-tool/oem-custom-tool.log", target_dir + "/app/oem-custom/");
    copy_file_or_dir("/var/local/oem-custom-tool/oem-custom-tool-bk.log", target_dir + "/app/oem-custom/");
    copy_file_or_dir("/root/.cache/isocustomizer-agent/iso-customizer-agent/iso-customizer-agent.log", target_dir + "/app/oem-custom/");
    // 授权管理客户端(1020及之后版本日志)
    copy_file_or_dir("/var/log/uos/uos-license-agent", target_dir + "/app/uos-activator/log/");
    copy_file_or_dir("/var/log/uos/uos-activator-kms", target_dir + "/app/uos-activator/log/");
    // 磁盘管理器
    copy_file_or_dir("/var/log/deepin/deepin-diskmanager-service/Log", target_dir + "/app/deepin-diskmanager/");
    // 窗口管理器
    runProcess({"lspci", "-v"}, (target_dir + "/app/kwin/lspci_VGA.log").c_str(), "VGA", 19);
    // 安卓容器
    copy_file_or_dir("/usr/share/log/log.txt", target_dir + "/app/kbox/");
    // 日志收集工具
    copy_file_or_dir("/var/log/deepin/deepin-log-viewer-service", target_dir + "/app/deepin-log-viewer/");
}

void OpsLogExport::exportSystemLogs()
{
    // 系统
    execute_command({"dmesg", "-T"}, target_dir + "/system/dmesg_system.log");
    execute_command({"journalctl"}, target_dir + "/system/journalctl.log");
    execute_command({"journalctl", "-b", "-0"}, target_dir + "/system/journalctl-0.log");
    execute_command({"journalctl", "-b", "-1"}, target_dir + "/system/journalctl-1.log");
    execute_command({"journalctl", "-xb"}, target_dir + "/system/journalctl-xb.log");
    copy_file_or_dir("/var/log/apt/history.log", target_dir + "/system/");
    copy_file_or_dir("/var/log/alternatives.log", target_dir + "/system/");
    copy_file_or_dir("/var/log/kern.log", target_dir + "/system/");
    copy_file_or_dir("/var/log/syslog", target_dir + "/system/");
    copy_file_or_dir("/var/log/dpkg.log", target_dir + "/system/");
    // xorg /var/log/目录下所有log文件
    {
        QStringList xorgFiles = expandPathWithWildcardIterator("/var/log/Xorg*");
        if (!xorgFiles.isEmpty()) {
            QStringList cpArgs;
            cpArgs << "cp" << "-rf" << xorgFiles << QString::fromStdString(target_dir + "/system/");
            runProcess(cpArgs);
        }
    }
}

void OpsLogExport::exportKernelLogs()
{
    // 内核
    copy_file_or_dir("/etc/product-info", target_dir + "/kernel/");
    execute_command({"uname", "-a"}, target_dir + "/kernel/uname-a.log");
    execute_command({"dmesg"}, target_dir + "/kernel/dmesg.log");
    copy_file_or_dir("/sys/firmware/acpi/tables/DSDT", target_dir + "/kernel/");
    copy_file_or_dir("/var/log/lightdm/lightdm.log", target_dir + "/kernel/");
    {
        QStringList xorgFiles = expandPathWithWildcardIterator("/var/log/Xorg.0.log*");
        if (!xorgFiles.isEmpty()) {
            QStringList cpArgs;
            cpArgs << "cp" << "-rf" << xorgFiles << QString::fromStdString(target_dir + "/kernel/");
            runProcess(cpArgs);
        }
    }
    runProcess({"lspci", "-vvv"}, (target_dir + "/kernel/lspci_VGA.log").c_str(), "VGA c", 12);
    runProcess({"dmesg"}, (target_dir + "/kernel/dmesg_network.log").c_str(), "iwlwifi", 0);
    execute_command({"journalctl", "--system"}, target_dir + "/kernel/journalctl_system.log");
    // ⽆法识别声卡问题⽇志
    execute_command({"lshw", "-c", "sound"}, target_dir + "/kernel/sound_info.log");
    // 龙芯内核
    copy_file_or_dir("/var/log/kern.log", target_dir + "/kernel/");
}

void OpsLogExport::exportDDELogs()
{
    // 文件管理器
    copy_file_or_dir("/var/log/deepin/dde-file-manager-daemon", target_dir + "/dde/dde-file-manager/");
    copy_file_or_dir("/var/log/messages", target_dir + "/dde/");
    copy_file_or_dir("/var/log/syslog", target_dir + "/dde/");
    execute_command({"coredumpctl", "list"}, target_dir + "/dde/coredumpctl.log");
    execute_command({"free", "-m"}, target_dir + "/dde/free-m.log");   // 查看内存情况，输出内容截图或保存
    execute_command({"udisksctl", "dump"}, target_dir + "/dde/udiskctl_dump.txt");
    execute_command({"df", "-h"}, target_dir + "/dde/df-h.txt");
    copy_file_or_dir("/var/log/journalLog", target_dir + "/dde/");
}

void OpsLogExport::exportHWLogs()
{
    // hw-info
    execute_command({"dmidecode", "-t", "0"}, target_dir + "/system_info.txt");
    execute_command({"dmidecode", "-t", "11"}, target_dir + "/system_info.txt");
    execute_command({"cat", "/etc/hw_version"}, target_dir + "/system_info.txt");
    execute_command({"echo"}, target_dir + "/system_info.txt");
    execute_command({"/usr/sbin/hwfirmware", "-v"}, target_dir + "/system_info.txt");
    execute_command({"echo"}, target_dir + "/system_info.txt");
    execute_command({"lscpu"}, target_dir + "/system_info.txt");
}

void OpsLogExport::exportOSVersionLogs()
{
    execute_command({"uname", "-a"}, target_dir + "/info-version.txt");
    execute_command({"echo"}, target_dir + "/info-version.txt");
    execute_command({"cat", "/etc/os-version"}, target_dir + "/info-version.txt");
    execute_command({"echo"}, target_dir + "/info-version.txt");
    execute_command({"echo", "-n" "开发者模式开启状态："}, target_dir + "/info-version.txt");
    execute_command({"cat", "/var/lib/deepin/developer-mode/enabled"}, target_dir + "/info-version.txt");
    execute_command({"echo", "\\n"}, target_dir + "/info-version.txt");
    execute_command({"uos-activator-cmd", "-q"}, target_dir + "/info-version.txt");
}

void OpsLogExport::exportAdditionalLogs()
{
    // hisi日志：仅在海思麒麟设备中存在，不存在时不视为异常
    copy_file_or_dir("/var/log/hisi", target_dir + "/hisi/");
    
    // journal日志：完整导出/var/log/journal目录下的所有内容
    copy_file_or_dir("/var/log/journal", target_dir + "/journal/");
}

void OpsLogExport::exportAptLogs()
{
    // apt日志：完整导出/var/log/apt目录下的所有内容
    copy_file_or_dir("/var/log/apt", target_dir);
}

void OpsLogExport::exportUosSteLogs()
{
    // uos-ste日志：完整导出/var/log/uos-ste目录下的所有内容
    copy_file_or_dir("/var/log/uos-ste", target_dir);
}

void OpsLogExport::exportUosSteTwoLogs()
{
    // uosste_logs日志：完整导出/var/log/uosste_logs目录下的所有内容
    copy_file_or_dir("/var/log/uosste_logs", target_dir);
}
