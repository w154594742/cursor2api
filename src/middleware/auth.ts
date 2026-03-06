/**
 * auth.ts - API Key 验证中间件
 * 作者: wangqiupei
 *
 * 从 Authorization 头中提取 Bearer token 并验证
 * 如果未配置 API Keys，则跳过验证（向后兼容）
 */

import type { Request, Response, NextFunction } from 'express';
import { getConfig } from '../config.js';

/**
 * API Key 验证中间件
 */
export function validateApiKey(req: Request, res: Response, next: NextFunction): void {
    const config = getConfig();

    // 如果未配置 API Keys，跳过验证（向后兼容）
    if (!config.apiKeys || config.apiKeys.length === 0) {
        return next();
    }

    // 提取 Authorization 头（兼容大小写）
    const authHeader = req.headers.authorization || req.headers.Authorization as string;

    if (!authHeader) {
        console.warn('[Auth] 缺少 Authorization 头');
        res.status(401).json({
            type: 'error',
            error: {
                type: 'authentication_error',
                message: 'missing authorization header'
            }
        });
        return;
    }

    // 解析 Bearer token（不区分大小写）
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) {
        console.warn('[Auth] Authorization 头格式错误');
        res.status(401).json({
            type: 'error',
            error: {
                type: 'authentication_error',
                message: 'invalid authorization header format, expected: Bearer <token>'
            }
        });
        return;
    }

    const providedKey = match[1];

    // 验证 API Key
    if (!config.apiKeys.includes(providedKey)) {
        const keyPrefix = providedKey.substring(0, 8);
        console.warn(`[Auth] 无效的 API Key: ${keyPrefix}...`);
        res.status(401).json({
            type: 'error',
            error: {
                type: 'authentication_error',
                message: 'invalid api key'
            }
        });
        return;
    }

    // 验证通过，记录日志（只显示前缀）
    const keyPrefix = providedKey.substring(0, 8);
    console.log(`[Auth] API Key 验证通过: ${keyPrefix}...`);
    next();
}
