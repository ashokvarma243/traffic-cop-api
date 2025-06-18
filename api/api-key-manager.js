// api-key-manager.js
const crypto = require('crypto');

class TrafficCopAPIKeyManager {
    constructor() {
        this.apiKeys = new Map();
        this.revokedKeys = new Set();
        
        // Initialize with your existing test keys
        this.initializeTestKeys();
    }
    
    // Initialize existing test keys
    initializeTestKeys() {
        const testKeys = [
            {
                key: 'tc_test_123',
                data: {
                    id: 'test_pub',
                    publisherName: 'Test Publisher',
                    email: 'test@example.com',
                    website: 'https://test.com',
                    plan: 'professional',
                    createdAt: new Date().toISOString(),
                    status: 'active'
                }
            }
        ];
        
        testKeys.forEach(item => {
            this.apiKeys.set(item.key, item.data);
        });
    }
    
    // Step 1: Generate unique API key
    generateAPIKey(publisherData) {
        // Create timestamp for uniqueness
        const timestamp = Date.now();
        
        // Generate random bytes (24 bytes = 48 hex characters)
        const randomBytes = crypto.randomBytes(24).toString('hex');
        
        // Create checksum for integrity
        const checksum = crypto.createHash('sha256')
            .update(`${timestamp}${randomBytes}${publisherData.email}`)
            .digest('hex')
            .substring(0, 8);
        
        // Combine into final API key
        const apiKey = `tc_live_${timestamp}_${randomBytes}_${checksum}`;
        
        return apiKey;
    }
    
    // Step 2: Create publisher metadata
    createPublisherData(publisherInfo, apiKey) {
        const publisherData = {
            id: `pub_${Date.now()}`,
            apiKey: apiKey,
            publisherName: publisherInfo.name || publisherInfo.website,
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
                lastResetDate: new Date().toISOString()
            },
            security: {
                rateLimits: this.getRateLimits(publisherInfo.plan),
                allowedIPs: [] // Can be restricted later
            }
        };
        
        return publisherData;
    }
    
    // Step 3: Calculate expiration dates
    calculateExpiration(plan) {
        const now = new Date();
        
        switch(plan) {
            case 'trial':
                return new Date(now.getTime() + (14 * 24 * 60 * 60 * 1000)); // 14 days
            case 'starter':
                return new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000)); // 1 year
            case 'professional':
                return new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000)); // 1 year
            case 'enterprise':
                return null; // No expiration
            default:
                return new Date(now.getTime() + (7 * 24 * 60 * 60 * 1000)); // 7 days
        }
    }
    
    // Step 4: Set permissions based on plan
    getPermissions(plan) {
        const basePermissions = ['analyze', 'dashboard'];
        
        switch(plan) {
            case 'starter':
                return [...basePermissions];
            case 'professional':
                return [...basePermissions, 'advanced_analytics', 'alerts'];
            case 'enterprise':
                return [...basePermissions, 'advanced_analytics', 'alerts', 'api_access', 'custom_rules'];
            default:
                return ['analyze']; // Trial
        }
    }
    
    // Step 5: Set rate limits
    getRateLimits(plan) {
        switch(plan) {
            case 'starter':
                return { requestsPerMonth: 100000, requestsPerMinute: 100 };
            case 'professional':
                return { requestsPerMonth: 1000000, requestsPerMinute: 500 };
            case 'enterprise':
                return { requestsPerMonth: -1, requestsPerMinute: 1000 }; // Unlimited
            default:
                return { requestsPerMonth: 10000, requestsPerMinute: 10 }; // Trial
        }
    }
    
    // Step 6: Complete API key creation process
    createPublisher(publisherInfo) {
        try {
            // Generate unique API key
            const apiKey = this.generateAPIKey(publisherInfo);
            
            // Create publisher data
            const publisherData = this.createPublisherData(publisherInfo, apiKey);
            
            // Store in memory (in production, use database)
            this.apiKeys.set(apiKey, publisherData);
            
            // Return complete result
            return {
                success: true,
                apiKey: apiKey,
                publisherId: publisherData.id,
                plan: publisherData.plan,
                expiresAt: publisherData.expiresAt,
                permissions: publisherData.permissions,
                setupUrl: `https://your-domain.vercel.app/setup?key=${apiKey}`,
                dashboardUrl: `https://your-domain.vercel.app/dashboard?key=${apiKey}`,
                message: 'API key generated successfully'
            };
            
        } catch (error) {
            return {
                success: false,
                error: 'Failed to generate API key',
                details: error.message
            };
        }
    }
    
    // Step 7: Validate API keys
    validateAPIKey(apiKey) {
        // Check if key exists
        if (!this.apiKeys.has(apiKey)) {
            return { valid: false, reason: 'Invalid API key' };
        }
        
        // Check if revoked
        if (this.revokedKeys.has(apiKey)) {
            return { valid: false, reason: 'API key revoked' };
        }
        
        const keyData = this.apiKeys.get(apiKey);
        
        // Check expiration
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return { valid: false, reason: 'API key expired' };
        }
        
        // Check status
        if (keyData.status !== 'active') {
            return { valid: false, reason: 'API key inactive' };
        }
        
        // Update usage
        keyData.usage.totalRequests++;
        keyData.usage.lastUsed = new Date().toISOString();
        
        return { valid: true, data: keyData };
    }
}

module.exports = TrafficCopAPIKeyManager;
