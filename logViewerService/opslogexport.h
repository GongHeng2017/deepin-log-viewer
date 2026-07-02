// SPDX-FileCopyrightText: 2025 - 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef OPS_LOG_EXPORT_H
#define OPS_LOG_EXPORT_H

#include <string>
#include <QStringList>

class OpsLogExport {
public:
    // callerUid/callerGid：调用 DBus 的前端用户身份，用于将导出目录 chown 给该用户，
    // 使其能以自身身份读取 root 收集的系统日志（权限收紧为 0700/0600，仅 caller 可读）。
    explicit OpsLogExport(const std::string& target, uint callerUid, uint callerGid);

    void run();

private:
    std::string target_dir;
    uint m_callerUid;
    uint m_callerGid;

    void createOpsLogDirStruct(const QString &outDir);

    bool path_exists(const std::string& path);
    void copy_file_or_dir(const std::string& src, const std::string& dst_dir);
    void execute_command(const QStringList &args, const std::string &output_file);
    void setDirectoryPermissionsSafe(const std::string& dir_path);

    // 验证目标目录在 /var/log 下（目录由 root 通过 QTemporaryDir 随机创建）
    bool ensureSafeTargetDir();

    void exportAppLogs();
    void exportSystemLogs();
    void exportKernelLogs();
    void exportDDELogs();
    void exportHWLogs();
    void exportOSVersionLogs();
    void exportAdditionalLogs();
    void exportAptLogs();
    void exportUosSteLogs();
    void exportUosSteTwoLogs();
};

#endif
