// api/api-key-manager.js
const crypto = require('crypto');
const { kv } = require('@vercel/kv');

class TrafficCopAPIKeyManager {
    constructor() {
        // All data stored in Vercel KV - no in-memory storage
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

    // Create new publisher and store in traffic-cop-api-keys database
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

            // Store in Vercel KV with multiple indexes
            await kv.set(`api_key:${apiKey}`, publisherData);
            await kv.set(`publisher:${publisherData.id}`, publisherData);
            await kv.set(`email:${publisherInfo.email}`, publisherData.id);

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

    // Validate API key and update usage statistics
    async validateAPIKey(apiKey) {
        try {
            const keyData = await kv.get(`api_key:${apiKey}`);

            if (!keyData) {
                return { valid: false, reason: 'Invalid API key' };
            }

            // Check expiration
            if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
                return { valid: false, reason: 'API key expired' };
            }

            // Check status
            if (keyData.status !== 'active') {
                return { valid: false, reason: 'API key inactive' };
            }

            // Update usage statistics
            keyData.usage.totalRequests++;
            keyData.usage.lastUsed = new Date().toISOString();
            
            // Update daily usage
            const today = new Date().toDateString();
            const lastReset = new Date(keyData.usage.lastDailyReset).toDateString();
            if (today !== lastReset) {
                keyData.usage.dailyRequests = 1;
                keyData.usage.lastDailyReset = new Date().toISOString();
            } else {
                keyData.usage.dailyRequests++;
            }

            // Update monthly usage
            const thisMonth = new Date().getMonth();
            const lastResetMonth = new Date(keyData.usage.lastResetDate).getMonth();
            if (thisMonth !== lastResetMonth) {
                keyData.usage.monthlyRequests = 1;
                keyData.usage.lastResetDate = new Date().toISOString();
            } else {
                keyData.usage.monthlyRequests++;
            }

            // Save updated data
            await kv.set(`api_key:${apiKey}`, keyData);

            return { valid: true, data: keyData };

        } catch (error) {
            console.error('Traffic Cop KV Error (validateAPIKey):', {
                operation: 'validateAPIKey',
                apiKey: apiKey.substring(0, 20) + '...',
                error: error.message,
                timestamp: new Date().toISOString()
            });
            
            return { valid: false, reason: 'Database error' };
        }
    }

    // Get publisher by email
    async getPublisherByEmail(email) {
        try {
            const publisherId = await kv.get(`email:${email}`);
            if (publisherId) {
                return await kv.get(`publisher:${publisherId}`);
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
            const keyData = await kv.get(`api_key:${apiKey}`);
            
            if (keyData) {
                keyData.status = status;
                keyData.updatedAt = new Date().toISOString();
                await kv.set(`api_key:${apiKey}`, keyData);
                await kv.set(`publisher:${keyData.id}`, keyData);
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
            const keyData = await kv.get(`api_key:${apiKey}`);
            
            if (keyData) {
                return {
                    success: true,
                    usage: keyData.usage,
                    rateLimits: keyData.security.rateLimits,
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
}

module.exports = TrafficCopAPIKeyManager;
