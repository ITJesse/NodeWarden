# NodeWarden 项目指南

本项目是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端（类似于 Vaultwarden，但专为 Cloudflare 边缘计算平台设计）。

## 项目概览

- **核心功能**：提供 Bitwarden 兼容的 API，支持密码、笔记、卡片、身份存储，支持附件上传，支持 TOTP/Passkey。
- **目标用户**：个人单用户使用（不支持多用户/组织功能）。
- **主要技术栈**：
  - **运行时**：Cloudflare Workers (TypeScript)
  - **数据库**：Cloudflare D1 (SQLite-based)
  - **文件存储**：Cloudflare R2 (S3-compatible)
  - **开发工具**：Wrangler (Cloudflare CLI)

## 项目结构

```text
src/
├── index.ts          # Worker 入口，负责初始化数据库和跨域处理
├── router.ts         # 手动实现的路由逻辑，处理 API 路由分发
├── handlers/         # 各个业务模块的 API 处理逻辑（如 ciphers, accounts, sync 等）
├── services/         # 核心服务模块
│   ├── auth.ts       # 身份验证与 JWT 处理
│   ├── storage.ts    # D1 数据库交互层
│   └── ratelimit.ts  # 速率限制服务
├── types/            # TypeScript 类型定义
└── utils/            # 通用工具函数（加密、响应格式化等）
migrations/           # D1 数据库迁移脚本
```

## 关键开发约定

1.  **数据库架构同步**：
    - **重要**：必须保持 `src/services/storage.ts` 中的 `SCHEMA_STATEMENTS` 数组与 `migrations/0001_init.sql` 中的 SQL 语句同步。项目在启动时会检查并执行 `SCHEMA_STATEMENTS` 以确保环境自动初始化。
2.  **单用户设计**：
    - 项目仅支持首个注册的用户。注册完成后，`config` 表中的 `registered` 键会被设为 `true`，随后注册接口将关闭。
3.  **API 兼容性**：
    - API 路径和响应格式必须严格遵循 Bitwarden 客户端协议。
4.  **速率限制**：
    - 所有的写入操作（POST, PUT, DELETE）和同步操作（`/api/sync`）都受到速率限制保护，逻辑位于 `RateLimitService` 中。

## 常用命令

- **本地开发**：
  ```bash
  npm run dev
  ```
- **部署到 Cloudflare**：
  ```bash
  npm run deploy
  ```
- **手动创建数据库（首次设置）**：
  ```bash
  npx wrangler d1 create nodewarden-db
  npx wrangler r2 bucket create nodewarden-attachments
  ```

## 常见问题解答 (FAQ)

- **为什么不使用 Hono？**：本项目为了保持极致的轻量级和对 Web API 的直接控制，选择了手动路由实现。
- **数据安全性**：采用端到端加密，主密码哈希存储，数据加密逻辑由客户端完成。
