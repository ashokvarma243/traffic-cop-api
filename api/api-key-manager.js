// api/api-key-manager.js
const crypto = require('crypto');

class TrafficCopAPIKeyManager {
    constructor() {
        this.kv = null; // Will be set by server.js
        this.kvPrefix = 'tc_api_'; // Match server.js pattern
    }

    // Set KV instance from server.js
    setKV(kvInstance) {
        this.kv = kvInstance;
    }

    // Ensure KV is available
    async ensureKVReady() {
        if (!this.kv) {
            throw new Error('KV not available - call setKV() first');
        }
        return true;
    }

    // Generate cryptographically secure API key
    generateAPIKey(publisherData) {
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(24).toString('hex');
        const checksum = crypto.createHash('sha256')
            .update(`${timestamp}${randomBytes}${publisherData.email}`)
            .digest('hex')
            .substring(0, 8);
        return `tc_live_${timestamp}_${randomBytes}_${checksum}`;
    }

    // Create comprehensive publisher metadata
    createPublisherData(publisherInfo, apiKey) {
        return {
            id: `pub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            apiKey: apiKey,
            publisherName: publisherInfo.name || this.extractDomainName(publisherInfo.website),
            email: publisherInfo.email,
            website: publisherInfo.website,
            plan: publisherInfo.plan || 'starter',
            createdAt: new Date().toISOString(),
            expiresAt: this.calculateExpiration(publisherInfo.plan),
            status: 'active',
            permissions: this.getPermissions(publisherInfo.plan),
            usage: {
                totalRequests: 0,
                monthlyRequests: 0,
                lastUsed: null,
                lastResetDate: new Date().toISOString(),
                dailyRequests: 0,
                lastDailyReset: new Date().toISOString()
            },
            security: {
                rateLimits: this.getRateLimits(publisherInfo.plan),
                allowedIPs: [],
                allowedDomains: [publisherInfo.website],
                lastLoginAt: null,
                failedLoginAttempts: 0
            },
            billing: {
                plan: publisherInfo.plan || 'starter',
                billingCycle: 'monthly',
                nextBillingDate: this.calculateNextBilling(),
                isActive: true
            }
        };
    }

    // Extract clean domain name for publisher name
    extractDomainName(website) {
        try {
            const url = new URL(website.startsWith('http') ? website : `https://${website}`);
            return url.hostname.replace('www.', '');
        } catch {
            return website;
        }
    }

    // Calculate expiration dates based on plan
    calculateExpiration(plan) {
        const now = new Date();
        switch (plan) {
            case 'trial':
                return new Date(now.getTime() + (14 * 24 * 60 * 60 * 1000));
            case 'starter':
            case 'professional':
                return new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000));
            case 'enterprise':
                return null;
            default:
                return new Date(now.getTime() + (7 * 24 * 60 * 60 * 1000));
        }
    }

    // Calculate next billing date
    calculateNextBilling() {
        const now = new Date();
        return new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000));
    }

    // Set permissions based on subscription plan
    getPermissions(plan) {
        const basePermissions = ['analyze', 'dashboard'];
        switch (plan) {
            case 'trial':
                return ['analyze'];
            case 'starter':
                return [...basePermissions, 'basic_analytics'];
            case 'professional':
                return [...basePermissions, 'advanced_analytics', 'alerts', 'custom_rules'];
            case 'enterprise':
                return [...basePermissions, 'advanced_analytics', 'alerts', 'api_access', 'custom_rules', 'white_label', 'priority_support'];
            default:
                return ['analyze'];
        }
    }

    // Set rate limits based on subscription plan
    getRateLimits(plan) {
        switch (plan) {
            case 'trial':
                return { 
                    requestsPerMonth: 10000, 
                    requestsPerMinute: 10,
                    requestsPerDay: 500
                };
            case 'starter':
                return { 
                    requestsPerMonth: 100000, 
                    requestsPerMinute: 100,
                    requestsPerDay: 5000
                };
            case 'professional':
                return { 
                    requestsPerMonth: 1000000, 
                    requestsPerMinute: 500,
                    requestsPerDay: 50000
                };
            case 'enterprise':
                return { 
                    requestsPerMonth: -1,
                    requestsPerMinute: 1000,
                    requestsPerDay: -1
                };
            default:
                return { 
                    requestsPerMonth: 1000, 
                    requestsPerMinute: 5,
                    requestsPerDay: 100
                };
        }
    }

    // Store API key with metadata (using tc_api_ prefix)
    async storeAPIKey(apiKeyData) {
        try {
            await this.ensureKVReady();
            
            const keyData = {
                ...apiKeyData,
                createdAt: new Date().toISOString(),
                lastUsed: new Date().toISOString(),
                requestCount: 0,
                status: 'active'
            };
            
            // Store API key data with tc_api_ prefix
            await this.kv.set(`${this.kvPrefix}key:${apiKeyData.apiKey}`, JSON.stringify(keyData));
            
            // Store publisher mapping
            await this.kv.set(`${this.kvPrefix}publisher:${apiKeyData.publisherId}`, apiKeyData.apiKey);
            
            // Add to active keys list
            await this.kv.sadd(`${this.kvPrefix}active_keys`, apiKeyData.apiKey);
            
            console.log(`🔑 API key stored: ${apiKeyData.apiKey.substring(0, 20)}...`);
            
            return keyData;
            
        } catch (error) {
            console.error('API key storage error:', error);
            throw error;
        }
    }

    // Create new publisher and store in KV
    async createPublisher(publisherInfo) {
        try {
            // Validate required fields
            if (!publisherInfo.email || !publisherInfo.website) {
                return {
                    success: false,
                    error: 'Email and website are required'
                };
            }

            // Check if email already exists
            const existingPublisher = await this.getPublisherByEmail(publisherInfo.email);
            if (existingPublisher) {
                return {
                    success: false,
                    error: 'Email already registered'
                };
            }

            // Generate unique API key
            const apiKey = this.generateAPIKey(publisherInfo);
            const publisherData = this.createPublisherData(publisherInfo, apiKey);

            // Store using the storeAPIKey method (consistent with server.js)
            await this.storeAPIKey({
                apiKey: apiKey,
                publisherId: publisherData.id,
                publisherName: publisherData.publisherName,
                email: publisherData.email,
                website: publisherData.website,
                plan: publisherData.plan,
                maxRequests: publisherData.security.rateLimits.requestsPerMonth,
                features: publisherData.permissions
            });

            // Also store email mapping with tc_api_ prefix
            await this.kv.set(`${this.kvPrefix}email:${publisherInfo.email}`, publisherData.id);

            return {
                success: true,
                apiKey: apiKey,
                publisherId: publisherData.id,
                publisherName: publisherData.publisherName,
                plan: publisherData.plan,
                expiresAt: publisherData.expiresAt,
                permissions: publisherData.permissions,
                rateLimits: publisherData.security.rateLimits,
                setupUrl: `https://traffic-cop-apii.vercel.app/setup?key=${apiKey}`,
                dashboardUrl: `https://traffic-cop-apii.vercel.app/publisher-login.html`,
                integrationCode: this.generateIntegrationCode(apiKey, publisherInfo.website),
                message: 'API key generated and stored in traffic-cop-api-keys database'
            };

        } catch (error) {
            console.error('Traffic Cop KV Error (createPublisher):', {
                operation: 'createPublisher',
                email: publisherInfo.email,
                error: error.message,
                timestamp: new Date().toISOString()
            });
            
            return {
                success: false,
                error: 'Failed to generate API key',
                details: error.message
            };
        }
    }

    // Generate integration code for new publishers
    generateIntegrationCode(apiKey, website) {
        return `<!-- Traffic Cop Integration for ${website} -->
<script src="https://traffic-cop-apii.vercel.app/traffic-cop-sdk.js"></script>
<script>
  TrafficCop.init('${apiKey}', {
    mode: 'monitor',
    blockThreshold: 80,
    challengeThreshold: 60,
    debug: false,
    website: '${website}'
  });
</script>`;
    }

    // Validate API key (compatible with server.js)
    async validateAPIKey(apiKey) {
        try {
            await this.ensureKVReady();
            
            const keyDataStr = await this.kv.get(`${this.kvPrefix}key:${apiKey}`);
            if (!keyDataStr) {
                return { valid: false, reason: 'API key not found' };
            }
            
            const keyData = JSON.parse(keyDataStr);
            
            // Check if key is active
            if (keyData.status !== 'active') {
                return { valid: false, reason: 'API key is inactive' };
            }
            
            // Check expiration if exists
            if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
                return { valid: false, reason: 'API key expired' };
            }
            
            // Update last used timestamp and request count
            keyData.lastUsed = new Date().toISOString();
            keyData.requestCount = (keyData.requestCount || 0) + 1;
            
            await this.kv.set(`${this.kvPrefix}key:${apiKey}`, JSON.stringify(keyData));
            
            return { 
                valid: true, 
                keyData: keyData,
                publisherId: keyData.publisherId,
                plan: keyData.plan,
                website: keyData.website
            };
            
        } catch (error) {
            console.error('API key validation error:', error);
            return { valid: false, reason: 'Validation error' };
        }
    }

    // Get publisher by email (using tc_api_ prefix)
    async getPublisherByEmail(email) {
        try {
            await this.ensureKVReady();
            const publisherId = await this.kv.get(`${this.kvPrefix}email:${email}`);
            if (publisherId) {
                const publisherApiKey = await this.kv.get(`${this.kvPrefix}publisher:${publisherId}`);
                if (publisherApiKey) {
                    const keyDataStr = await this.kv.get(`${this.kvPrefix}key:${publisherApiKey}`);
                    return keyDataStr ? JSON.parse(keyDataStr) : null;
                }
            }
            return null;
        } catch (error) {
            console.error('Error getting publisher by email:', error);
            return null;
        }
    }

    // Update publisher status
    async updatePublisherStatus(apiKey, status) {
        try {
            await this.ensureKVReady();
            const keyDataStr = await this.kv.get(`${this.kvPrefix}key:${apiKey}`);
            
            if (keyDataStr) {
                const keyData = JSON.parse(keyDataStr);
                keyData.status = status;
                keyData.updatedAt = new Date().toISOString();
                await this.kv.set(`${this.kvPrefix}key:${apiKey}`, JSON.stringify(keyData));
                return { success: true };
            }
            
            return { success: false, error: 'Publisher not found' };
        } catch (error) {
            console.error('Error updating publisher status:', error);
            return { success: false, error: error.message };
        }
    }

    // Get usage statistics for a publisher
    async getUsageStats(apiKey) {
        try {
            await this.ensureKVReady();
            const keyDataStr = await this.kv.get(`${this.kvPrefix}key:${apiKey}`);
            
            if (keyDataStr) {
                const keyData = JSON.parse(keyDataStr);
                return {
                    success: true,
                    usage: keyData.usage || {
                        totalRequests: keyData.requestCount || 0,
                        lastUsed: keyData.lastUsed
                    },
                    rateLimits: this.getRateLimits(keyData.plan),
                    plan: keyData.plan,
                    status: keyData.status
                };
            }
            
            return { success: false, error: 'API key not found' };
        } catch (error) {
            console.error('Error getting usage stats:', error);
            return { success: false, error: error.message };
        }
    }

    // Check rate limits
    async checkRateLimit(apiKey, requestType = 'analyze') {
        try {
            const keyDataStr = await this.kv.get(`${this.kvPrefix}key:${apiKey}`);
            if (!keyDataStr) {
                return { allowed: false, reason: 'Invalid API key' };
            }

            const keyData = JSON.parse(keyDataStr);
            const rateLimits = this.getRateLimits(keyData.plan);
            
            // Check monthly limit
            if (rateLimits.requestsPerMonth !== -1 && 
                keyData.requestCount >= rateLimits.requestsPerMonth) {
                return { allowed: false, reason: 'Monthly limit exceeded' };
            }

            return { allowed: true, rateLimits: rateLimits };
        } catch (error) {
            console.error('Rate limit check error:', error);
            return { allowed: false, reason: 'Rate limit check failed' };
        }
    }
}

module.exports = TrafficCopAPIKeyManager;
