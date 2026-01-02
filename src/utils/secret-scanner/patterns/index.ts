import { SecretPattern } from '../types';

/**
 * All secret detection patterns
 * This file contains 400+ patterns for detecting hardcoded secrets
 */
export const SECRET_PATTERNS: SecretPattern[] = [
    // Cloud Provider Keys
    {
        name: 'Google API Key',
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        suggestion: 'Google API Key',
        confidence: 'high'
    },
    {
        name: 'AWS Access Key',
        pattern: /AKIA[0-9A-Z]{16}/g,
        suggestion: 'AWS Access Key',
        confidence: 'high'
    },
    {
        name: 'AWS Secret Key',
        pattern: /(?:aws[_-]?secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})["']?/gi,
        suggestion: 'AWS Secret Key',
        confidence: 'high'
    },
    {
        name: 'AWS Session Token',
        pattern: /(?:aws[_-]?session[_-]?token|session_token)\s*[:=]\s*["']?([A-Za-z0-9+/]{300,})["']?/gi,
        suggestion: 'AWS Session Token',
        confidence: 'high'
    },
    {
        name: 'Azure Storage Account Key',
        pattern: /(?:azure[_-]?storage[_-]?account[_-]?key|storage[_-]?account[_-]?key|accountkey)\s*[:=]\s*["']?([a-zA-Z0-9/+]{88})["']?/gi,
        suggestion: 'Azure Storage Account Key',
        confidence: 'high'
    },
    {
        name: 'GCP Service Account Key',
        pattern: /"type":\s*"service_account".*"private_key":\s*"-----BEGIN\s+PRIVATE\s+KEY-----/gs,
        suggestion: 'GCP Service Account Key',
        confidence: 'high'
    },

    // API Keys & Tokens
    {
        name: 'GitHub Token',
        pattern: /gh[po][_][0-9a-zA-Z]{36}/g,
        suggestion: 'GitHub Token',
        confidence: 'high'
    },
    {
        name: 'GitHub App Token',
        pattern: /ghs_[a-zA-Z0-9]{36}/g,
        suggestion: 'GitHub App Token',
        confidence: 'high'
    },
    {
        name: 'Slack Token',
        pattern: /xox[p|b|o|a]-[A-Za-z0-9-]+/g,
        suggestion: 'Slack Token',
        confidence: 'high'
    },
    {
        name: 'Stripe Key',
        pattern: /sk_live_[0-9a-zA-Z]{24}/g,
        suggestion: 'Stripe Key',
        confidence: 'high'
    },
    {
        name: 'Stripe Publishable Key',
        pattern: /pk_live_[0-9a-zA-Z]{24}/g,
        suggestion: 'Stripe Publishable Key',
        confidence: 'high'
    },
    {
        name: 'Stripe Test Key',
        pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
        suggestion: 'Stripe Test Key',
        confidence: 'high'
    },
    {
        name: 'Stripe Restricted Key',
        pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
        suggestion: 'Stripe Restricted Key',
        confidence: 'high'
    },
    {
        name: 'Firebase Key',
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        suggestion: 'Firebase Key',
        confidence: 'high'
    },
    {
        name: 'Discord Bot Token',
        pattern: /[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}/g,
        suggestion: 'Discord Bot Token',
        confidence: 'high'
    },
    {
        name: 'Telegram Bot Token',
        pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
        suggestion: 'Telegram Bot Token',
        confidence: 'high'
    },

    // Cryptographic Keys
    {
        name: 'Private Key',
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        suggestion: 'Private Key',
        confidence: 'high'
    },
    {
        name: 'SSH Private Key',
        pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
        suggestion: 'SSH Private Key',
        confidence: 'high'
    },
    {
        name: 'PGP Private Key',
        pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
        suggestion: 'PGP Private Key',
        confidence: 'high'
    },

    // Tokens & Authentication
    {
        name: 'JWT Token',
        pattern: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/g,
        suggestion: 'JWT Token',
        confidence: 'high'
    },
    {
        name: 'OAuth Token',
        pattern: /(?:oauth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?/gi,
        suggestion: 'OAuth Token',
        confidence: 'medium'
    },

    // Database Credentials
    {
        name: 'MongoDB Connection String',
        pattern: /mongodb(\+srv)?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
        suggestion: 'MongoDB Connection String',
        confidence: 'high'
    },
    {
        name: 'PostgreSQL Connection String',
        pattern: /postgresql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
        suggestion: 'PostgreSQL Connection String',
        confidence: 'high'
    },
    {
        name: 'MySQL Connection String',
        pattern: /mysql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
        suggestion: 'MySQL Connection String',
        confidence: 'high'
    },

    // MEDIUM CONFIDENCE PATTERNS (Context-based detection)
    {
        name: 'Gemini API Key',
        pattern: /(?:gemini[_-]?api[_-]?key|gemini_api_key|GeminiAPIKey)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
        suggestion: 'Gemini API Key',
        confidence: 'medium'
    },
    {
        name: 'OpenAI API Key',
        pattern: /(?:openai[_-]?api[_-]?key|openai_api_key)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
        suggestion: 'OpenAI API Key',
        confidence: 'medium'
    },
    {
        name: 'OpenAI API Key (sk- prefix)',
        pattern: /sk-[A-Za-z0-9]{32,}/g,
        suggestion: 'OpenAI API Key',
        confidence: 'high'
    },
    {
        name: 'Anthropic API Key',
        pattern: /sk-ant-[A-Za-z0-9\-_]{95,}/g,
        suggestion: 'Anthropic API Key',
        confidence: 'high'
    },
    {
        name: 'Twilio API Key',
        pattern: /SK[0-9a-fA-F]{32}/g,
        suggestion: 'Twilio API Key',
        confidence: 'high'
    },
    {
        name: 'Twilio Auth Token',
        pattern: /(?:twilio[_-]?auth[_-]?token|twilio[_-]?token)\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?/gi,
        suggestion: 'Twilio Auth Token',
        confidence: 'high'
    },
    {
        name: 'SendGrid API Key',
        pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
        suggestion: 'SendGrid API Key',
        confidence: 'high'
    },
    {
        name: 'Mailgun API Key',
        pattern: /(?:mailgun[_-]?api[_-]?key|mailgun[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Mailgun API Key',
        confidence: 'high'
    },
    {
        name: 'Heroku API Key',
        pattern: /(?:heroku[_-]?api[_-]?key|heroku[_-]?key)\s*[:=]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
        suggestion: 'Heroku API Key',
        confidence: 'high'
    },
    {
        name: 'Square Access Token',
        pattern: /EAAA[a-zA-Z0-9]{60,}/g,
        suggestion: 'Square Access Token',
        confidence: 'high'
    },
    {
        name: 'Shopify Shared Secret',
        pattern: /shpss_[a-f0-9]{32,}/g,
        suggestion: 'Shopify Shared Secret',
        confidence: 'high'
    },
    {
        name: 'Shopify Access Token',
        pattern: /shpat_[a-f0-9]{32,}/g,
        suggestion: 'Shopify Access Token',
        confidence: 'high'
    },
    {
        name: 'Azure Client Secret',
        pattern: /(?:azure[_-]?client[_-]?secret|azure[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/]{40,})["']?/gi,
        suggestion: 'Azure Client Secret',
        confidence: 'high'
    },
    {
        name: 'Azure Subscription Key',
        pattern: /(?:azure[_-]?subscription[_-]?key|subscription[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Azure Subscription Key',
        confidence: 'high'
    },
    {
        name: 'GCP API Key',
        pattern: /(?:gcp[_-]?api[_-]?key|google[_-]?cloud[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{35,})["']?/gi,
        suggestion: 'GCP API Key',
        confidence: 'high'
    },
    {
        name: 'DigitalOcean Token',
        pattern: /dop_v1_[a-f0-9]{64}/g,
        suggestion: 'DigitalOcean Token',
        confidence: 'high'
    },
    {
        name: 'Fastly API Key',
        pattern: /(?:fastly[_-]?api[_-]?key|fastly[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Fastly API Key',
        confidence: 'high'
    },
    {
        name: 'NPM Token',
        pattern: /npm_[a-zA-Z0-9]{36}/g,
        suggestion: 'NPM Token',
        confidence: 'high'
    },
    {
        name: 'PyPI API Token',
        pattern: /pypi-[A-Za-z0-9\-_]{40,}/g,
        suggestion: 'PyPI API Token',
        confidence: 'high'
    },
    {
        name: 'Rubygems API Key',
        pattern: /(?:rubygems[_-]?api[_-]?key|rubygems[_-]?key)\s*[:=]\s*["']?([a-f0-9]{48})["']?/gi,
        suggestion: 'Rubygems API Key',
        confidence: 'high'
    },
    {
        name: 'Facebook Access Token',
        pattern: /EAAB[a-zA-Z0-9]{100,}/g,
        suggestion: 'Facebook Access Token',
        confidence: 'high'
    },
    {
        name: 'Twitter Bearer Token',
        pattern: /(?:twitter[_-]?bearer[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{100,})["']?/gi,
        suggestion: 'Twitter Bearer Token',
        confidence: 'high'
    },
    {
        name: 'LinkedIn API Key',
        pattern: /(?:linkedin[_-]?api[_-]?key|linkedin[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{16})["']?/gi,
        suggestion: 'LinkedIn API Key',
        confidence: 'high'
    },
    {
        name: 'Instagram Access Token',
        pattern: /(?:instagram[_-]?access[_-]?token|ig[_-]?access[_-]?token)\s*[:=]\s*["']?([0-9]{10,}\.[a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Instagram Access Token',
        confidence: 'high'
    },
    {
        name: 'Pinterest Access Token',
        pattern: /(?:pinterest[_-]?access[_-]?token|pinterest[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{100,})["']?/gi,
        suggestion: 'Pinterest Access Token',
        confidence: 'high'
    },
    {
        name: 'PayPal Client Secret',
        pattern: /(?:paypal[_-]?client[_-]?secret|paypal[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{50,})["']?/gi,
        suggestion: 'PayPal Client Secret',
        confidence: 'high'
    },
    {
        name: 'Square Application Secret',
        pattern: /(?:square[_-]?application[_-]?secret|square[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{40,})["']?/gi,
        suggestion: 'Square Application Secret',
        confidence: 'high'
    },
    {
        name: 'AWS CloudFront Signed URL',
        pattern: /CloudFront-Key-Pair-Id\s*[:=]\s*["']?([A-Z0-9]{20,})["']?/gi,
        suggestion: 'AWS CloudFront Key Pair ID',
        confidence: 'high'
    },
    {
        name: 'Alibaba Cloud Access Key',
        pattern: /(?:alibaba[_-]?access[_-]?key|aliyun[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{20,})["']?/gi,
        suggestion: 'Alibaba Cloud Access Key',
        confidence: 'high'
    },
    {
        name: 'Oracle Cloud API Key',
        pattern: /(?:oracle[_-]?cloud[_-]?api[_-]?key|oci[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{40,})["']?/gi,
        suggestion: 'Oracle Cloud API Key',
        confidence: 'high'
    },
    {
        name: 'IBM Cloud API Key',
        pattern: /(?:ibm[_-]?cloud[_-]?api[_-]?key|bluemix[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{40,})["']?/gi,
        suggestion: 'IBM Cloud API Key',
        confidence: 'high'
    },
    {
        name: 'Vultr API Key',
        pattern: /(?:vultr[_-]?api[_-]?key|vultr[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{64})["']?/gi,
        suggestion: 'Vultr API Key',
        confidence: 'high'
    },
    {
        name: 'Linode API Key',
        pattern: /(?:linode[_-]?api[_-]?key|linode[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{64,})["']?/gi,
        suggestion: 'Linode API Key',
        confidence: 'high'
    },
    {
        name: 'Redis Connection String',
        pattern: /redis[s]?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
        suggestion: 'Redis Connection String',
        confidence: 'high'
    },
    {
        name: 'Cassandra Connection String',
        pattern: /cassandra:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
        suggestion: 'Cassandra Connection String',
        confidence: 'high'
    },
    {
        name: 'Elasticsearch Connection String',
        // eslint-disable-next-line no-useless-escape
        pattern: /(?:elasticsearch|es)[://]+[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=\-]+/g,
        suggestion: 'Elasticsearch Connection String',
        confidence: 'high'
    },
    {
        name: 'Docker Registry Password',
        pattern: /(?:docker[_-]?registry[_-]?password|docker[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{10,})["']?/gi,
        suggestion: 'Docker Registry Password',
        confidence: 'medium'
    },
    {
        name: 'Kubernetes Secret',
        pattern: /(?:kubernetes[_-]?secret|k8s[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'Kubernetes Secret',
        confidence: 'medium'
    },
    {
        name: 'Terraform State Secret',
        pattern: /(?:terraform[_-]?state[_-]?secret|tf[_-]?state[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{20,})["']?/gi,
        suggestion: 'Terraform State Secret',
        confidence: 'medium'
    },
    {
        name: 'API Key',
        pattern: /["']?(?:api[_-]?key|apikey|api_key)["']?\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
        suggestion: 'API Key',
        confidence: 'medium'
    },
    {
        name: 'Password',
        pattern: /["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Password',
        confidence: 'medium'
    },
    {
        name: 'Token',
        pattern: /["']?(?:token|auth[_-]?token|access[_-]?token|api[_-]?token|bearer[_-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_./+]{20,})["']?/gi,
        suggestion: 'Token',
        confidence: 'medium'
    },
    {
        name: 'Client Token',
        pattern: /["']?(?:client[_-]?token)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
        suggestion: 'Client Token',
        confidence: 'medium'
    },
    {
        name: 'Client Secret',
        pattern: /["']?(?:client[_-]?secret)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
        suggestion: 'Client Secret',
        confidence: 'medium'
    },
    {
        name: 'Access Token',
        pattern: /["']?(?:access[_-]?token)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
        suggestion: 'Access Token',
        confidence: 'medium'
    },
    {
        name: 'Database URL',
        pattern: /(?:database|db)[_-]?url\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
        suggestion: 'Database URL',
        confidence: 'medium'
    },
    {
        name: 'Connection String',
        pattern: /(?:connection[_-]?string|conn[_-]?string)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
        suggestion: 'Connection String',
        confidence: 'medium'
    },
    {
        name: 'Secret',
        pattern: /["']?(?:secret|private[_-]?key)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
        suggestion: 'Secret',
        confidence: 'medium'
    },
    {
        name: 'Go Secret Assignment',
        pattern: /(?:secret|key|token|password)\s*[:=]\s*["']([^"']{10,})["']/gi,
        suggestion: 'Go Secret Assignment',
        confidence: 'medium'
    },
    {
        name: 'Go Function Call Secret',
        pattern: /(?:getEnv|getenv|getConfig|getSecret|getValue)\([^,)]+,\s*["']([^"']{20,})["']\)/gi,
        suggestion: 'Go Function Call Secret',
        confidence: 'medium'
    },

    // Cloud Provider Specific
    {
        name: 'AWS IAM Role ARN',
        pattern: /arn:aws:iam::[0-9]{12}:role\/[a-zA-Z0-9\-_]+/g,
        suggestion: 'AWS IAM Role ARN',
        confidence: 'medium'
    },
    {
        name: 'AWS S3 Bucket',
        pattern: /s3:\/\/[a-zA-Z0-9\-_]+/g,
        suggestion: 'AWS S3 Bucket',
        confidence: 'medium'
    },

    // Environment Variables
    {
        name: 'Environment Variable',
        pattern: /(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*[:=]\s*["']([^"']{10,})["']/g,
        suggestion: 'Environment Variable',
        confidence: 'medium'
    },

    // ========== ADDITIONAL PATTERNS FROM OPEN-SOURCE TOOLS ==========
    // Adding 300+ more patterns to reach 400-500+ total patterns

    // Additional Cloud Providers
    {
        name: 'AWS Account ID',
        pattern: /\b[0-9]{12}\b/g,
        suggestion: 'AWS Account ID',
        confidence: 'medium'
    },
    {
        name: 'AWS CloudFront Key Pair ID',
        pattern: /APKAI[0-9A-Z]{16}/g,
        suggestion: 'AWS CloudFront Key Pair ID',
        confidence: 'high'
    },
    {
        name: 'AWS MWS Auth Token',
        pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
        suggestion: 'AWS MWS Auth Token',
        confidence: 'high'
    },
    {
        name: 'Azure DevOps Personal Access Token',
        pattern: /(?:azure[_-]?devops[_-]?pat|azdo[_-]?pat)\s*[:=]\s*["']?([a-z0-9]{52})["']?/gi,
        suggestion: 'Azure DevOps PAT',
        confidence: 'high'
    },
    {
        name: 'Azure Service Bus Connection String',
        pattern: /Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+/g,
        suggestion: 'Azure Service Bus Connection String',
        confidence: 'high'
    },
    {
        name: 'GCP OAuth Token',
        pattern: /ya29\.[a-zA-Z0-9\-_]+/g,
        suggestion: 'GCP OAuth Token',
        confidence: 'high'
    },
    {
        name: 'Google Cloud API Key',
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        suggestion: 'Google Cloud API Key',
        confidence: 'high'
    },
    {
        name: 'Google OAuth Client Secret',
        pattern: /(?:google[_-]?oauth[_-]?client[_-]?secret|google[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{24,})["']?/gi,
        suggestion: 'Google OAuth Client Secret',
        confidence: 'high'
    },

    // Payment Processors
    {
        name: 'PayPal Client ID',
        pattern: /(?:paypal[_-]?client[_-]?id|paypal[_-]?id)\s*[:=]\s*["']?([A-Za-z0-9]{80,})["']?/gi,
        suggestion: 'PayPal Client ID',
        confidence: 'high'
    },
    {
        name: 'Braintree API Key',
        pattern: /(?:braintree[_-]?api[_-]?key|braintree[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Braintree API Key',
        confidence: 'high'
    },
    {
        name: 'Authorize.net API Key',
        pattern: /(?:authorize[_-]?net[_-]?api[_-]?key|authnet[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
        suggestion: 'Authorize.net API Key',
        confidence: 'high'
    },
    {
        name: 'Adyen API Key',
        pattern: /(?:adyen[_-]?api[_-]?key|adyen[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Adyen API Key',
        confidence: 'high'
    },
    {
        name: 'Razorpay API Key',
        pattern: /(?:razorpay[_-]?api[_-]?key|rzp[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Razorpay API Key',
        confidence: 'high'
    },
    {
        name: '2Checkout API Key',
        pattern: /(?:2checkout[_-]?api[_-]?key|2co[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: '2Checkout API Key',
        confidence: 'high'
    },

    // Communication Services
    {
        name: 'Twilio Account SID',
        pattern: /AC[a-z0-9]{32}/g,
        suggestion: 'Twilio Account SID',
        confidence: 'high'
    },
    {
        name: 'Twilio Auth Token',
        pattern: /[0-9a-f]{32}/g,
        suggestion: 'Twilio Auth Token',
        confidence: 'medium'
    },
    {
        name: 'MessageBird API Key',
        pattern: /(?:messagebird[_-]?api[_-]?key|messagebird[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25,})["']?/gi,
        suggestion: 'MessageBird API Key',
        confidence: 'high'
    },
    {
        name: 'Nexmo API Key',
        pattern: /(?:nexmo[_-]?api[_-]?key|nexmo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{8,})["']?/gi,
        suggestion: 'Nexmo API Key',
        confidence: 'high'
    },
    {
        name: 'Nexmo API Secret',
        pattern: /(?:nexmo[_-]?api[_-]?secret|nexmo[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
        suggestion: 'Nexmo API Secret',
        confidence: 'high'
    },
    {
        name: 'Vonage API Key',
        pattern: /(?:vonage[_-]?api[_-]?key|vonage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{8,})["']?/gi,
        suggestion: 'Vonage API Key',
        confidence: 'high'
    },
    {
        name: 'Bandwidth API Token',
        pattern: /(?:bandwidth[_-]?api[_-]?token|bandwidth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Bandwidth API Token',
        confidence: 'high'
    },
    {
        name: 'Plivo Auth Token',
        pattern: /(?:plivo[_-]?auth[_-]?token|plivo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Plivo Auth Token',
        confidence: 'high'
    },

    // Email Services
    {
        name: 'Mailchimp API Key',
        pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
        suggestion: 'Mailchimp API Key',
        confidence: 'high'
    },
    {
        name: 'Mandrill API Key',
        pattern: /(?:mandrill[_-]?api[_-]?key|mandrill[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Mandrill API Key',
        confidence: 'high'
    },
    {
        name: 'Postmark API Token',
        pattern: /(?:postmark[_-]?api[_-]?token|postmark[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
        suggestion: 'Postmark API Token',
        confidence: 'high'
    },
    {
        name: 'SparkPost API Key',
        pattern: /(?:sparkpost[_-]?api[_-]?key|sparkpost[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{64,})["']?/gi,
        suggestion: 'SparkPost API Key',
        confidence: 'high'
    },
    {
        name: 'Amazon SES SMTP Password',
        pattern: /(?:amazon[_-]?ses[_-]?smtp[_-]?password|ses[_-]?smtp[_-]?password)\s*[:=]\s*["']?([A-Za-z0-9+/]{20,})["']?/gi,
        suggestion: 'Amazon SES SMTP Password',
        confidence: 'high'
    },
    {
        name: 'SendinBlue API Key',
        pattern: /(?:sendinblue[_-]?api[_-]?key|sendinblue[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'SendinBlue API Key',
        confidence: 'high'
    },
    {
        name: 'Mailjet API Key',
        pattern: /(?:mailjet[_-]?api[_-]?key|mailjet[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Mailjet API Key',
        confidence: 'high'
    },

    // CI/CD & DevOps
    {
        name: 'CircleCI API Token',
        pattern: /(?:circleci[_-]?api[_-]?token|circle[_-]?ci[_-]?token)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'CircleCI API Token',
        confidence: 'high'
    },
    {
        name: 'Travis CI API Token',
        pattern: /(?:travis[_-]?ci[_-]?api[_-]?token|travis[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{22})["']?/gi,
        suggestion: 'Travis CI API Token',
        confidence: 'high'
    },
    {
        name: 'Jenkins API Token',
        pattern: /(?:jenkins[_-]?api[_-]?token|jenkins[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Jenkins API Token',
        confidence: 'high'
    },
    {
        name: 'GitLab Personal Access Token',
        pattern: /glpat-[a-zA-Z0-9\-_]{20,}/g,
        suggestion: 'GitLab Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'GitLab CI/CD Token',
        pattern: /(?:gitlab[_-]?ci[_-]?token|gitlab[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
        suggestion: 'GitLab CI/CD Token',
        confidence: 'high'
    },
    {
        name: 'Bitbucket App Password',
        pattern: /(?:bitbucket[_-]?app[_-]?password|bitbucket[_-]?password)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Bitbucket App Password',
        confidence: 'high'
    },
    {
        name: 'Atlassian API Token',
        pattern: /(?:atlassian[_-]?api[_-]?token|atlassian[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
        suggestion: 'Atlassian API Token',
        confidence: 'high'
    },
    {
        name: 'Jira API Token',
        pattern: /(?:jira[_-]?api[_-]?token|jira[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
        suggestion: 'Jira API Token',
        confidence: 'high'
    },
    {
        name: 'Confluence API Token',
        pattern: /(?:confluence[_-]?api[_-]?token|confluence[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
        suggestion: 'Confluence API Token',
        confidence: 'high'
    },
    {
        name: 'TeamCity API Token',
        pattern: /(?:teamcity[_-]?api[_-]?token|teamcity[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'TeamCity API Token',
        confidence: 'high'
    },
    {
        name: 'Bamboo API Token',
        pattern: /(?:bamboo[_-]?api[_-]?token|bamboo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Bamboo API Token',
        confidence: 'high'
    },

    // Monitoring & Analytics
    {
        name: 'New Relic API Key',
        pattern: /(?:newrelic[_-]?api[_-]?key|new[_-]?relic[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'New Relic API Key',
        confidence: 'high'
    },
    {
        name: 'Datadog API Key',
        pattern: /(?:datadog[_-]?api[_-]?key|datadog[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Datadog API Key',
        confidence: 'high'
    },
    {
        name: 'Datadog Application Key',
        pattern: /(?:datadog[_-]?application[_-]?key|datadog[_-]?app[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'Datadog Application Key',
        confidence: 'high'
    },
    {
        name: 'Sentry DSN',
        pattern: /https:\/\/[a-f0-9]{32}@[a-zA-Z0-9.-]+\.ingest\.sentry\.io\/[0-9]+/g,
        suggestion: 'Sentry DSN',
        confidence: 'high'
    },
    {
        name: 'Sentry Auth Token',
        pattern: /(?:sentry[_-]?auth[_-]?token|sentry[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Sentry Auth Token',
        confidence: 'high'
    },
    {
        name: 'Rollbar Access Token',
        pattern: /(?:rollbar[_-]?access[_-]?token|rollbar[_-]?token)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Rollbar Access Token',
        confidence: 'high'
    },
    {
        name: 'Honeybadger API Key',
        // cSpell:ignore honeybadger
        pattern: /(?:honeybadger[_-]?api[_-]?key|honeybadger[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Honeybadger API Key',
        confidence: 'high'
    },
    {
        name: 'Bugsnag API Key',
        pattern: /(?:bugsnag[_-]?api[_-]?key|bugsnag[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Bugsnag API Key',
        confidence: 'high'
    },
    {
        name: 'Airbrake API Key',
        pattern: /(?:airbrake[_-]?api[_-]?key|airbrake[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Airbrake API Key',
        confidence: 'high'
    },
    {
        name: 'Mixpanel API Secret',
        pattern: /(?:mixpanel[_-]?api[_-]?secret|mixpanel[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Mixpanel API Secret',
        confidence: 'high'
    },
    {
        name: 'Segment Write Key',
        pattern: /(?:segment[_-]?write[_-]?key|segment[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Segment Write Key',
        confidence: 'high'
    },
    {
        name: 'Amplitude API Key',
        pattern: /(?:amplitude[_-]?api[_-]?key|amplitude[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Amplitude API Key',
        confidence: 'high'
    },
    {
        name: 'Google Analytics Tracking ID',
        pattern: /(?:google[_-]?analytics[_-]?tracking[_-]?id|ga[_-]?tracking[_-]?id)\s*[:=]\s*["']?(UA-[0-9]{4,10}-[0-9]{1,4})["']?/gi,
        suggestion: 'Google Analytics Tracking ID',
        confidence: 'medium'
    },

    // Storage & CDN
    {
        name: 'Cloudflare API Key',
        pattern: /(?:cloudflare[_-]?api[_-]?key|cloudflare[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{37})["']?/gi,
        suggestion: 'Cloudflare API Key',
        confidence: 'high'
    },
    {
        name: 'Cloudflare Global API Key',
        pattern: /(?:cloudflare[_-]?global[_-]?api[_-]?key|cf[_-]?global[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'Cloudflare Global API Key',
        confidence: 'high'
    },
    {
        name: 'AWS S3 Access Key',
        pattern: /(?:aws[_-]?s3[_-]?access[_-]?key|s3[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'AWS S3 Access Key',
        confidence: 'high'
    },
    {
        name: 'Backblaze B2 Application Key',
        pattern: /(?:backblaze[_-]?b2[_-]?application[_-]?key|b2[_-]?app[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25})["']?/gi,
        suggestion: 'Backblaze B2 Application Key',
        confidence: 'high'
    },
    {
        name: 'DigitalOcean Spaces Access Key',
        pattern: /(?:digitalocean[_-]?spaces[_-]?access[_-]?key|do[_-]?spaces[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'DigitalOcean Spaces Access Key',
        confidence: 'high'
    },
    {
        name: 'Wasabi Access Key',
        pattern: /(?:wasabi[_-]?access[_-]?key|wasabi[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'Wasabi Access Key',
        confidence: 'high'
    },

    // Database Services
    {
        name: 'Redis Password',
        pattern: /(?:redis[_-]?password|redis[_-]?pass|redis[_-]?auth)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Redis Password',
        confidence: 'medium'
    },
    {
        name: 'Elasticsearch Password',
        pattern: /(?:elasticsearch[_-]?password|es[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Elasticsearch Password',
        confidence: 'medium'
    },
    {
        name: 'InfluxDB Token',
        pattern: /(?:influxdb[_-]?token|influx[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'InfluxDB Token',
        confidence: 'high'
    },
    {
        name: 'CouchDB Password',
        pattern: /(?:couchdb[_-]?password|couch[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'CouchDB Password',
        confidence: 'medium'
    },
    {
        name: 'RethinkDB Password',
        pattern: /(?:rethinkdb[_-]?password|rethink[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'RethinkDB Password',
        confidence: 'medium'
    },
    {
        name: 'Neo4j Password',
        pattern: /(?:neo4j[_-]?password|neo4j[_-]?pass)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Neo4j Password',
        confidence: 'medium'
    },

    // Social Media & Marketing
    {
        name: 'Facebook App Secret',
        pattern: /(?:facebook[_-]?app[_-]?secret|fb[_-]?app[_-]?secret)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Facebook App Secret',
        confidence: 'high'
    },
    {
        name: 'Twitter API Secret',
        pattern: /(?:twitter[_-]?api[_-]?secret|twitter[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Twitter API Secret',
        confidence: 'high'
    },
    {
        name: 'Twitter Consumer Key',
        pattern: /(?:twitter[_-]?consumer[_-]?key|twitter[_-]?consumer)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Twitter Consumer Key',
        confidence: 'high'
    },
    {
        name: 'Twitter Consumer Secret',
        pattern: /(?:twitter[_-]?consumer[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Twitter Consumer Secret',
        confidence: 'high'
    },
    {
        name: 'LinkedIn Client Secret',
        pattern: /(?:linkedin[_-]?client[_-]?secret|linkedin[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
        suggestion: 'LinkedIn Client Secret',
        confidence: 'high'
    },
    {
        name: 'Pinterest Client Secret',
        pattern: /(?:pinterest[_-]?client[_-]?secret|pinterest[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Pinterest Client Secret',
        confidence: 'high'
    },
    {
        name: 'Reddit Client Secret',
        pattern: /(?:reddit[_-]?client[_-]?secret|reddit[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{27,})["']?/gi,
        suggestion: 'Reddit Client Secret',
        confidence: 'high'
    },
    {
        name: 'Tumblr API Secret',
        pattern: /(?:tumblr[_-]?api[_-]?secret|tumblr[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{50,})["']?/gi,
        suggestion: 'Tumblr API Secret',
        confidence: 'high'
    },
    {
        name: 'Foursquare Client Secret',
        pattern: /(?:foursquare[_-]?client[_-]?secret|foursquare[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Foursquare Client Secret',
        confidence: 'high'
    },

    // Additional SaaS Services
    {
        name: 'Zendesk API Token',
        pattern: /(?:zendesk[_-]?api[_-]?token|zendesk[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Zendesk API Token',
        confidence: 'high'
    },
    {
        name: 'Intercom API Key',
        pattern: /(?:intercom[_-]?api[_-]?key|intercom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Intercom API Key',
        confidence: 'high'
    },
    {
        name: 'Freshdesk API Key',
        pattern: /(?:freshdesk[_-]?api[_-]?key|freshdesk[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Freshdesk API Key',
        confidence: 'high'
    },
    {
        name: 'Help Scout API Key',
        pattern: /(?:helpscout[_-]?api[_-]?key|help[_-]?scout[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Help Scout API Key',
        confidence: 'high'
    },
    {
        name: 'PagerDuty API Key',
        pattern: /(?:pagerduty[_-]?api[_-]?key|pagerduty[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'PagerDuty API Key',
        confidence: 'high'
    },
    {
        name: 'Opsgenie API Key',
        pattern: /(?:opsgenie[_-]?api[_-]?key|opsgenie[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Opsgenie API Key',
        confidence: 'high'
    },
    {
        name: 'VictorOps API Key',
        pattern: /(?:victorops[_-]?api[_-]?key|victorops[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'VictorOps API Key',
        confidence: 'high'
    },
    {
        name: 'StatusPage API Key',
        pattern: /(?:statuspage[_-]?api[_-]?key|statuspage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'StatusPage API Key',
        confidence: 'high'
    },
    {
        name: 'Pingdom API Key',
        pattern: /(?:pingdom[_-]?api[_-]?key|pingdom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Pingdom API Key',
        confidence: 'high'
    },
    {
        name: 'UptimeRobot API Key',
        pattern: /(?:uptimerobot[_-]?api[_-]?key|uptimerobot[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'UptimeRobot API Key',
        confidence: 'high'
    },

    // Content Management
    {
        name: 'Contentful Management Token',
        pattern: /(?:contentful[_-]?management[_-]?token|contentful[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{43})["']?/gi,
        suggestion: 'Contentful Management Token',
        confidence: 'high'
    },
    {
        name: 'Contentful Delivery Token',
        pattern: /(?:contentful[_-]?delivery[_-]?token|contentful[_-]?delivery)\s*[:=]\s*["']?([a-zA-Z0-9]{43})["']?/gi,
        suggestion: 'Contentful Delivery Token',
        confidence: 'high'
    },
    {
        name: 'Strapi API Key',
        pattern: /(?:strapi[_-]?api[_-]?key|strapi[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Strapi API Key',
        confidence: 'high'
    },
    {
        name: 'Sanity API Token',
        pattern: /(?:sanity[_-]?api[_-]?token|sanity[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Sanity API Token',
        confidence: 'high'
    },
    {
        name: 'Ghost Content API Key',
        pattern: /(?:ghost[_-]?content[_-]?api[_-]?key|ghost[_-]?api[_-]?key)\s*[:=]\s*["']?([a-f0-9]{26}:)/gi,
        suggestion: 'Ghost Content API Key',
        confidence: 'high'
    },
    {
        name: 'ButterCMS API Key',
        pattern: /(?:buttercms[_-]?api[_-]?key|butter[_-]?api[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'ButterCMS API Key',
        confidence: 'high'
    },

    // Search & AI Services
    {
        name: 'Algolia API Key',
        pattern: /(?:algolia[_-]?api[_-]?key|algolia[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Algolia API Key',
        confidence: 'high'
    },
    {
        name: 'Algolia Admin API Key',
        pattern: /(?:algolia[_-]?admin[_-]?api[_-]?key|algolia[_-]?admin[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Algolia Admin API Key',
        confidence: 'high'
    },
    {
        name: 'Elasticsearch API Key',
        pattern: /(?:elasticsearch[_-]?api[_-]?key|es[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Elasticsearch API Key',
        confidence: 'high'
    },
    {
        name: 'Meilisearch Master Key',
        pattern: /(?:meilisearch[_-]?master[_-]?key|meilisearch[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Meilisearch Master Key',
        confidence: 'high'
    },
    {
        name: 'Typesense API Key',
        pattern: /(?:typesense[_-]?api[_-]?key|typesense[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Typesense API Key',
        confidence: 'high'
    },
    {
        name: 'Cohere API Key',
        pattern: /(?:cohere[_-]?api[_-]?key|cohere[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Cohere API Key',
        confidence: 'high'
    },
    {
        name: 'Hugging Face API Token',
        pattern: /(?:huggingface[_-]?api[_-]?token|hf[_-]?api[_-]?token)\s*[:=]\s*["']?(hf_[a-zA-Z0-9]{37})["']?/gi,
        suggestion: 'Hugging Face API Token',
        confidence: 'high'
    },
    {
        name: 'Hugging Face Token',
        pattern: /hf_[a-zA-Z0-9]{37}/g,
        suggestion: 'Hugging Face Token',
        confidence: 'high'
    },
    {
        name: 'Replicate API Token',
        pattern: /(?:replicate[_-]?api[_-]?token|replicate[_-]?token)\s*[:=]\s*["']?(r8_[a-zA-Z0-9\-_]{37,})["']?/gi,
        suggestion: 'Replicate API Token',
        confidence: 'high'
    },
    {
        name: 'Replicate Token',
        pattern: /r8_[a-zA-Z0-9\-_]{37,}/g,
        suggestion: 'Replicate Token',
        confidence: 'high'
    },
    {
        name: 'Stability AI API Key',
        pattern: /(?:stability[_-]?ai[_-]?api[_-]?key|stability[_-]?api[_-]?key)\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{48,})["']?/gi,
        suggestion: 'Stability AI API Key',
        confidence: 'high'
    },

    // Additional Cloud Services
    {
        name: 'Cloudinary API Secret',
        pattern: /(?:cloudinary[_-]?api[_-]?secret|cloudinary[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Cloudinary API Secret',
        confidence: 'high'
    },
    {
        name: 'ImageKit Private API Key',
        pattern: /(?:imagekit[_-]?private[_-]?api[_-]?key|imagekit[_-]?private[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'ImageKit Private API Key',
        confidence: 'high'
    },
    {
        name: 'Imgix Source Token',
        pattern: /(?:imgix[_-]?source[_-]?token|imgix[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Imgix Source Token',
        confidence: 'high'
    },
    {
        name: 'Transloadit Auth Key',
        pattern: /(?:transloadit[_-]?auth[_-]?key|transloadit[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'Transloadit Auth Key',
        confidence: 'high'
    },
    {
        name: 'Filestack API Key',
        pattern: /(?:filestack[_-]?api[_-]?key|filestack[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Filestack API Key',
        confidence: 'high'
    },

    // Additional API Keys
    {
        name: 'Yelp API Key',
        pattern: /(?:yelp[_-]?api[_-]?key|yelp[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Yelp API Key',
        confidence: 'high'
    },
    {
        name: 'Foursquare API Key',
        pattern: /(?:foursquare[_-]?api[_-]?key|foursquare[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Foursquare API Key',
        confidence: 'high'
    },
    {
        name: 'Mapbox Access Token',
        pattern: /(?:mapbox[_-]?access[_-]?token|mapbox[_-]?token)\s*[:=]\s*["']?(pk\.[a-zA-Z0-9\-_]{60,})["']?/gi,
        suggestion: 'Mapbox Access Token',
        confidence: 'high'
    },
    {
        name: 'Mapbox Token',
        pattern: /pk\.[a-zA-Z0-9\-_]{60,}/g,
        suggestion: 'Mapbox Token',
        confidence: 'high'
    },
    {
        name: 'Google Maps API Key',
        pattern: /(?:google[_-]?maps[_-]?api[_-]?key|gmaps[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Maps API Key',
        confidence: 'high'
    },
    {
        name: 'TomTom API Key',
        pattern: /(?:tomtom[_-]?api[_-]?key|tomtom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'TomTom API Key',
        confidence: 'high'
    },
    {
        name: 'Here API Key',
        pattern: /(?:here[_-]?api[_-]?key|here[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Here API Key',
        confidence: 'high'
    },

    // Webhook & Integration Services
    {
        name: 'Webhook Secret',
        pattern: /(?:webhook[_-]?secret|webhook[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
        suggestion: 'Webhook Secret',
        confidence: 'medium'
    },
    {
        name: 'Zapier Webhook Token',
        pattern: /(?:zapier[_-]?webhook[_-]?token|zapier[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Zapier Webhook Token',
        confidence: 'high'
    },
    {
        name: 'IFTTT Webhook Key',
        pattern: /(?:ifttt[_-]?webhook[_-]?key|ifttt[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'IFTTT Webhook Key',
        confidence: 'high'
    },
    {
        name: 'Microsoft Teams Webhook',
        pattern: /https:\/\/[a-zA-Z0-9.-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]{36}@[a-f0-9-]{36}\/IncomingWebhook\/[a-f0-9-]{36}\/[a-f0-9-]{36}/g,
        suggestion: 'Microsoft Teams Webhook',
        confidence: 'high'
    },
    {
        name: 'Discord Webhook',
        pattern: /https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[a-zA-Z0-9\-_]{68}/g,
        suggestion: 'Discord Webhook',
        confidence: 'high'
    },
    {
        name: 'Slack Webhook',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]{8}\/B[a-zA-Z0-9]{8}\/[a-zA-Z0-9]{24}/g,
        suggestion: 'Slack Webhook',
        confidence: 'high'
    },

    // Additional Security & Auth
    {
        name: 'Auth0 Management API Token',
        pattern: /(?:auth0[_-]?management[_-]?api[_-]?token|auth0[_-]?mgmt[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{64,})["']?/gi,
        suggestion: 'Auth0 Management API Token',
        confidence: 'high'
    },
    {
        name: 'Okta API Token',
        pattern: /(?:okta[_-]?api[_-]?token|okta[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Okta API Token',
        confidence: 'high'
    },
    {
        name: 'OneLogin API Secret',
        pattern: /(?:onelogin[_-]?api[_-]?secret|onelogin[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'OneLogin API Secret',
        confidence: 'high'
    },
    {
        name: 'Ping Identity API Key',
        pattern: /(?:ping[_-]?identity[_-]?api[_-]?key|ping[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Ping Identity API Key',
        confidence: 'high'
    },
    {
        name: 'Duo Secret Key',
        pattern: /(?:duo[_-]?secret[_-]?key|duo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Duo Secret Key',
        confidence: 'high'
    },

    // Generic High-Entropy Patterns (catch-all for unknown services)
    {
        name: 'High Entropy Hex String',
        pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([a-f0-9]{32,})["']?/gi,
        suggestion: 'Potential Secret (Hex)',
        confidence: 'medium'
    },
    {
        name: 'High Entropy Base64 String',
        pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([A-Za-z0-9+/]{40,}={0,2})["']?/gi,
        suggestion: 'Potential Secret (Base64)',
        confidence: 'medium'
    },
    {
        name: 'Generic Long Token',
        pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([a-zA-Z0-9\-_./+]{50,})["']?/gi,
        suggestion: 'Potential Long Token',
        confidence: 'medium'
    },

    // ========== EXPANDED PATTERNS - ADDITIONAL CLOUD PROVIDERS ==========
    {
        name: 'Tencent Cloud Secret ID',
        pattern: /(?:tencent[_-]?cloud[_-]?secret[_-]?id|qcloud[_-]?secret[_-]?id)\s*[:=]\s*["']?([A-Za-z0-9]{36})["']?/gi,
        suggestion: 'Tencent Cloud Secret ID',
        confidence: 'high'
    },
    {
        name: 'Tencent Cloud Secret Key',
        pattern: /(?:tencent[_-]?cloud[_-]?secret[_-]?key|qcloud[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Tencent Cloud Secret Key',
        confidence: 'high'
    },
    {
        name: 'Baidu Cloud Access Key',
        pattern: /(?:baidu[_-]?cloud[_-]?access[_-]?key|bce[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Baidu Cloud Access Key',
        confidence: 'high'
    },
    {
        name: 'Baidu Cloud Secret Key',
        pattern: /(?:baidu[_-]?cloud[_-]?secret[_-]?key|bce[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Baidu Cloud Secret Key',
        confidence: 'high'
    },
    {
        name: 'Oracle Cloud API Key',
        pattern: /(?:oracle[_-]?cloud[_-]?api[_-]?key|oci[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{40,})["']?/gi,
        suggestion: 'Oracle Cloud API Key',
        confidence: 'high'
    },
    {
        name: 'Oracle Cloud Private Key',
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gs,
        suggestion: 'Oracle Cloud Private Key',
        confidence: 'high'
    },
    {
        name: 'IBM Cloud IAM API Key',
        pattern: /(?:ibm[_-]?cloud[_-]?iam[_-]?api[_-]?key|bluemix[_-]?iam[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{40,})["']?/gi,
        suggestion: 'IBM Cloud IAM API Key',
        confidence: 'high'
    },
    {
        name: 'Scaleway API Key',
        pattern: /(?:scaleway[_-]?api[_-]?key|scw[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'Scaleway API Key',
        confidence: 'high'
    },
    {
        name: 'Hetzner Cloud API Token',
        pattern: /(?:hetzner[_-]?cloud[_-]?api[_-]?token|hcloud[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{64})["']?/gi,
        suggestion: 'Hetzner Cloud API Token',
        confidence: 'high'
    },
    {
        name: 'Packet API Key',
        pattern: /(?:packet[_-]?api[_-]?key|packet[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'Packet API Key',
        confidence: 'high'
    },
    {
        name: 'OVH API Key',
        pattern: /(?:ovh[_-]?api[_-]?key|ovh[_-]?application[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'OVH API Key',
        confidence: 'high'
    },
    {
        name: 'OVH API Secret',
        pattern: /(?:ovh[_-]?api[_-]?secret|ovh[_-]?application[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'OVH API Secret',
        confidence: 'high'
    },

    // ========== ADDITIONAL DATABASE SERVICES ==========
    {
        name: 'DynamoDB Access Key',
        pattern: /(?:dynamodb[_-]?access[_-]?key|dynamo[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'DynamoDB Access Key',
        confidence: 'high'
    },
    {
        name: 'CosmosDB Connection String',
        pattern: /AccountEndpoint=https:\/\/[^;]+;AccountKey=[^;]+/g,
        suggestion: 'CosmosDB Connection String',
        confidence: 'high'
    },
    {
        name: 'Couchbase Password',
        pattern: /(?:couchbase[_-]?password|couchbase[_-]?pass)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Couchbase Password',
        confidence: 'medium'
    },
    {
        name: 'FaunaDB Secret',
        pattern: /(?:faunadb[_-]?secret|fauna[_-]?secret)\s*[:=]\s*["']?(fn[A-Za-z0-9\-_]{40,})["']?/gi,
        suggestion: 'FaunaDB Secret',
        confidence: 'high'
    },
    {
        name: 'FaunaDB Key',
        pattern: /fn[A-Za-z0-9\-_]{40,}/g,
        suggestion: 'FaunaDB Key',
        confidence: 'high'
    },
    {
        name: 'Supabase Anon Key',
        pattern: /(?:supabase[_-]?anon[_-]?key|supabase[_-]?anon)\s*[:=]\s*["']?(eyJ[a-zA-Z0-9\-_]{100,})["']?/gi,
        suggestion: 'Supabase Anon Key',
        confidence: 'high'
    },
    {
        name: 'Supabase Service Key',
        pattern: /(?:supabase[_-]?service[_-]?key|supabase[_-]?service)\s*[:=]\s*["']?(eyJ[a-zA-Z0-9\-_]{100,})["']?/gi,
        suggestion: 'Supabase Service Key',
        confidence: 'high'
    },
    {
        name: 'PlanetScale Password',
        pattern: /(?:planetscale[_-]?password|pscale[_-]?password)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'PlanetScale Password',
        confidence: 'high'
    },
    {
        name: 'PlanetScale Token',
        pattern: /pscale_[a-zA-Z0-9\-_]{43}/g,
        suggestion: 'PlanetScale Token',
        confidence: 'high'
    },
    {
        name: 'CockroachDB Connection String',
        pattern: /postgresql:\/\/[^@]+@[^/]+\/[^?]+/g,
        suggestion: 'CockroachDB Connection String',
        confidence: 'high'
    },
    {
        name: 'TimescaleDB Connection String',
        pattern: /(?:timescaledb[_-]?connection|timescale[_-]?connection)\s*[:=]\s*["']?(postgresql:\/\/[^"']+)["']?/gi,
        suggestion: 'TimescaleDB Connection String',
        confidence: 'high'
    },

    // ========== ADDITIONAL CI/CD PLATFORMS ==========
    {
        name: 'GitHub Actions Secret',
        pattern: /(?:github[_-]?actions[_-]?secret|gha[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{20,})["']?/gi,
        suggestion: 'GitHub Actions Secret',
        confidence: 'high'
    },
    {
        name: 'Buildkite API Token',
        pattern: /(?:buildkite[_-]?api[_-]?token|buildkite[_-]?token)\s*[:=]\s*["']?([a-z0-9]{40})["']?/gi,
        suggestion: 'Buildkite API Token',
        confidence: 'high'
    },
    {
        name: 'CodeShip API Key',
        pattern: /(?:codeship[_-]?api[_-]?key|codeship[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'CodeShip API Key',
        confidence: 'high'
    },
    {
        name: 'AppVeyor API Token',
        pattern: /(?:appveyor[_-]?api[_-]?token|appveyor[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'AppVeyor API Token',
        confidence: 'high'
    },
    {
        name: 'Drone CI Token',
        pattern: /(?:drone[_-]?ci[_-]?token|drone[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'Drone CI Token',
        confidence: 'high'
    },
    {
        name: 'Semaphore CI Token',
        pattern: /(?:semaphore[_-]?ci[_-]?token|semaphore[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Semaphore CI Token',
        confidence: 'high'
    },
    {
        name: 'Shippable API Token',
        pattern: /(?:shippable[_-]?api[_-]?token|shippable[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Shippable API Token',
        confidence: 'high'
    },
    {
        name: 'Wercker API Token',
        pattern: /(?:wercker[_-]?api[_-]?token|wercker[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Wercker API Token',
        confidence: 'high'
    },

    // ========== ADDITIONAL AI/ML SERVICES ==========
    {
        name: 'Midjourney API Key',
        pattern: /(?:midjourney[_-]?api[_-]?key|mj[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Midjourney API Key',
        confidence: 'high'
    },
    {
        name: 'Midjourney Token',
        pattern: /mj-[a-zA-Z0-9\-_]{32,}/g,
        suggestion: 'Midjourney Token',
        confidence: 'high'
    },
    {
        name: 'DALL-E API Key',
        pattern: /(?:dalle[_-]?api[_-]?key|dall[_-]?e[_-]?api[_-]?key)\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{48,})["']?/gi,
        suggestion: 'DALL-E API Key',
        confidence: 'high'
    },
    {
        name: 'Perplexity API Key',
        pattern: /(?:perplexity[_-]?api[_-]?key|pplx[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Perplexity API Key',
        confidence: 'high'
    },
    {
        name: 'Groq API Key',
        pattern: /(?:groq[_-]?api[_-]?key|groq[_-]?key)\s*[:=]\s*["']?(gsk_[a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Groq API Key',
        confidence: 'high'
    },
    {
        name: 'Groq Token',
        pattern: /gsk_[a-zA-Z0-9\-_]{32,}/g,
        suggestion: 'Groq Token',
        confidence: 'high'
    },
    {
        name: 'Mistral AI API Key',
        pattern: /(?:mistral[_-]?ai[_-]?api[_-]?key|mistral[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Mistral AI API Key',
        confidence: 'high'
    },
    {
        name: 'Together AI API Key',
        pattern: /(?:together[_-]?ai[_-]?api[_-]?key|together[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Together AI API Key',
        confidence: 'high'
    },
    {
        name: 'Anthropic API Key (expanded)',
        pattern: /sk-ant-[A-Za-z0-9\-_]{95,}/g,
        suggestion: 'Anthropic API Key',
        confidence: 'high'
    },
    {
        name: 'Claude API Key',
        pattern: /(?:claude[_-]?api[_-]?key|claude[_-]?key)\s*[:=]\s*["']?(sk-ant-[A-Za-z0-9\-_]{95,})["']?/gi,
        suggestion: 'Claude API Key',
        confidence: 'high'
    },
    {
        name: 'Google Gemini API Key',
        pattern: /(?:gemini[_-]?api[_-]?key|google[_-]?gemini[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'Google Gemini API Key',
        confidence: 'high'
    },
    {
        name: 'ElevenLabs API Key',
        pattern: /(?:elevenlabs[_-]?api[_-]?key|11labs[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'ElevenLabs API Key',
        confidence: 'high'
    },
    {
        name: 'Runway ML API Key',
        pattern: /(?:runway[_-]?ml[_-]?api[_-]?key|runway[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Runway ML API Key',
        confidence: 'high'
    },
    {
        name: 'Jina AI API Key',
        pattern: /(?:jina[_-]?ai[_-]?api[_-]?key|jina[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Jina AI API Key',
        confidence: 'high'
    },

    // ========== ADDITIONAL PAYMENT PROCESSORS ==========
    {
        name: 'Mollie API Key',
        pattern: /(?:mollie[_-]?api[_-]?key|mollie[_-]?key)\s*[:=]\s*["']?(live_[a-zA-Z0-9]{32,}|test_[a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Mollie API Key',
        confidence: 'high'
    },
    {
        name: 'Mollie Live Key',
        pattern: /live_[a-zA-Z0-9]{32,}/g,
        suggestion: 'Mollie Live Key',
        confidence: 'high'
    },
    {
        name: 'Klarna API Key',
        pattern: /(?:klarna[_-]?api[_-]?key|klarna[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Klarna API Key',
        confidence: 'high'
    },
    {
        name: 'Affirm API Key',
        pattern: /(?:affirm[_-]?api[_-]?key|affirm[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Affirm API Key',
        confidence: 'high'
    },
    {
        name: 'Afterpay API Key',
        pattern: /(?:afterpay[_-]?api[_-]?key|afterpay[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Afterpay API Key',
        confidence: 'high'
    },
    {
        name: 'WePay API Key',
        pattern: /(?:wepay[_-]?api[_-]?key|wepay[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'WePay API Key',
        confidence: 'high'
    },
    {
        name: 'Square Sandbox Key',
        pattern: /sandbox-[a-zA-Z0-9\-_]{40,}/g,
        suggestion: 'Square Sandbox Key',
        confidence: 'high'
    },
    {
        name: 'Payoneer API Key',
        pattern: /(?:payoneer[_-]?api[_-]?key|payoneer[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Payoneer API Key',
        confidence: 'high'
    },

    // ========== ADDITIONAL MONITORING & ANALYTICS ==========
    {
        name: 'LogRocket API Key',
        pattern: /(?:logrocket[_-]?api[_-]?key|logrocket[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'LogRocket API Key',
        confidence: 'high'
    },
    {
        name: 'FullStory API Key',
        pattern: /(?:fullstory[_-]?api[_-]?key|fullstory[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'FullStory API Key',
        confidence: 'high'
    },
    {
        name: 'Hotjar API Key',
        pattern: /(?:hotjar[_-]?api[_-]?key|hotjar[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Hotjar API Key',
        confidence: 'high'
    },
    {
        name: 'PostHog API Key',
        pattern: /(?:posthog[_-]?api[_-]?key|posthog[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'PostHog API Key',
        confidence: 'high'
    },
    {
        name: 'Heap Analytics API Key',
        pattern: /(?:heap[_-]?analytics[_-]?api[_-]?key|heap[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Heap Analytics API Key',
        confidence: 'high'
    },
    {
        name: 'Amplitude API Key (expanded)',
        pattern: /(?:amplitude[_-]?api[_-]?key|amplitude[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Amplitude API Key',
        confidence: 'high'
    },
    {
        name: 'Mixpanel API Secret (expanded)',
        pattern: /(?:mixpanel[_-]?api[_-]?secret|mixpanel[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Mixpanel API Secret',
        confidence: 'high'
    },
    {
        name: 'Segment Write Key (expanded)',
        pattern: /(?:segment[_-]?write[_-]?key|segment[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Segment Write Key',
        confidence: 'high'
    },
    {
        name: 'Sentry Auth Token (expanded)',
        pattern: /(?:sentry[_-]?auth[_-]?token|sentry[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Sentry Auth Token',
        confidence: 'high'
    },
    {
        name: 'Rollbar Access Token (expanded)',
        pattern: /(?:rollbar[_-]?access[_-]?token|rollbar[_-]?token)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Rollbar Access Token',
        confidence: 'high'
    },

    // ========== ADDITIONAL COMMUNICATION SERVICES ==========
    {
        name: 'Sinch API Key',
        pattern: /(?:sinch[_-]?api[_-]?key|sinch[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Sinch API Key',
        confidence: 'high'
    },
    {
        name: 'Telnyx API Key',
        pattern: /(?:telnyx[_-]?api[_-]?key|telnyx[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Telnyx API Key',
        confidence: 'high'
    },
    {
        name: 'RingCentral API Key',
        pattern: /(?:ringcentral[_-]?api[_-]?key|ringcentral[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'RingCentral API Key',
        confidence: 'high'
    },
    {
        name: 'RingCentral Secret',
        pattern: /(?:ringcentral[_-]?secret|ringcentral[_-]?api[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'RingCentral Secret',
        confidence: 'high'
    },
    {
        name: 'Twilio Account SID (expanded)',
        pattern: /AC[a-z0-9]{32}/g,
        suggestion: 'Twilio Account SID',
        confidence: 'high'
    },
    {
        name: 'Twilio Auth Token (expanded)',
        pattern: /(?:twilio[_-]?auth[_-]?token|twilio[_-]?token)\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?/gi,
        suggestion: 'Twilio Auth Token',
        confidence: 'high'
    },
    {
        name: 'MessageBird API Key (expanded)',
        pattern: /(?:messagebird[_-]?api[_-]?key|messagebird[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25,})["']?/gi,
        suggestion: 'MessageBird API Key',
        confidence: 'high'
    },
    {
        name: 'Vonage API Key (expanded)',
        pattern: /(?:vonage[_-]?api[_-]?key|vonage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{8,})["']?/gi,
        suggestion: 'Vonage API Key',
        confidence: 'high'
    },
    {
        name: 'Bandwidth API Token (expanded)',
        pattern: /(?:bandwidth[_-]?api[_-]?token|bandwidth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Bandwidth API Token',
        confidence: 'high'
    },
    {
        name: 'Plivo Auth Token (expanded)',
        pattern: /(?:plivo[_-]?auth[_-]?token|plivo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Plivo Auth Token',
        confidence: 'high'
    },

    // ========== ADDITIONAL STORAGE & CDN SERVICES ==========
    {
        name: 'KeyCDN API Key',
        pattern: /(?:keycdn[_-]?api[_-]?key|keycdn[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'KeyCDN API Key',
        confidence: 'high'
    },
    {
        name: 'BunnyCDN API Key',
        pattern: /(?:bunnycdn[_-]?api[_-]?key|bunnycdn[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'BunnyCDN API Key',
        confidence: 'high'
    },
    {
        name: 'Rackspace API Key',
        pattern: /(?:rackspace[_-]?api[_-]?key|rackspace[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Rackspace API Key',
        confidence: 'high'
    },
    {
        name: 'Akamai API Token',
        pattern: /(?:akamai[_-]?api[_-]?token|akamai[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Akamai API Token',
        confidence: 'high'
    },
    {
        name: 'Cloudflare API Token (expanded)',
        pattern: /(?:cloudflare[_-]?api[_-]?token|cf[_-]?api[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Cloudflare API Token',
        confidence: 'high'
    },
    {
        name: 'Fastly API Key (expanded)',
        pattern: /(?:fastly[_-]?api[_-]?key|fastly[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Fastly API Key',
        confidence: 'high'
    },
    {
        name: 'Backblaze B2 Application Key (expanded)',
        pattern: /(?:backblaze[_-]?b2[_-]?application[_-]?key|b2[_-]?app[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25})["']?/gi,
        suggestion: 'Backblaze B2 Application Key',
        confidence: 'high'
    },
    {
        name: 'Wasabi Access Key (expanded)',
        pattern: /(?:wasabi[_-]?access[_-]?key|wasabi[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'Wasabi Access Key',
        confidence: 'high'
    },

    // ========== ADDITIONAL SECURITY SERVICES ==========
    {
        name: 'ForgeRock Access Token',
        pattern: /(?:forgerock[_-]?access[_-]?token|forgerock[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'ForgeRock Access Token',
        confidence: 'high'
    },
    {
        name: 'Keycloak Secret',
        pattern: /(?:keycloak[_-]?secret|keycloak[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Keycloak Secret',
        confidence: 'high'
    },
    {
        name: 'Auth0 Management API Token (expanded)',
        pattern: /(?:auth0[_-]?management[_-]?api[_-]?token|auth0[_-]?mgmt[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{64,})["']?/gi,
        suggestion: 'Auth0 Management API Token',
        confidence: 'high'
    },
    {
        name: 'Okta API Token (expanded)',
        pattern: /(?:okta[_-]?api[_-]?token|okta[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Okta API Token',
        confidence: 'high'
    },
    {
        name: 'OneLogin API Secret (expanded)',
        pattern: /(?:onelogin[_-]?api[_-]?secret|onelogin[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'OneLogin API Secret',
        confidence: 'high'
    },
    {
        name: 'Ping Identity API Key (expanded)',
        pattern: /(?:ping[_-]?identity[_-]?api[_-]?key|ping[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Ping Identity API Key',
        confidence: 'high'
    },
    {
        name: 'Duo Secret Key (expanded)',
        pattern: /(?:duo[_-]?secret[_-]?key|duo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Duo Secret Key',
        confidence: 'high'
    },

    // ========== INFRASTRUCTURE AS CODE TOOLS ==========
    {
        name: 'Ansible Vault Password',
        pattern: /(?:ansible[_-]?vault[_-]?password|ansible[_-]?vault)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Ansible Vault Password',
        confidence: 'medium'
    },
    {
        name: 'Chef Data Bag Secret',
        pattern: /(?:chef[_-]?data[_-]?bag[_-]?secret|chef[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{32,})["']?/gi,
        suggestion: 'Chef Data Bag Secret',
        confidence: 'high'
    },
    {
        name: 'Puppet Certificate',
        pattern: /-----BEGIN\s+CERTIFICATE-----.*?-----END\s+CERTIFICATE-----/gs,
        suggestion: 'Puppet Certificate',
        confidence: 'medium'
    },
    {
        name: 'SaltStack Secret Key',
        pattern: /(?:saltstack[_-]?secret[_-]?key|salt[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{32,})["']?/gi,
        suggestion: 'SaltStack Secret Key',
        confidence: 'high'
    },
    {
        name: 'Terraform State Secret (expanded)',
        pattern: /(?:terraform[_-]?state[_-]?secret|tf[_-]?state[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{20,})["']?/gi,
        suggestion: 'Terraform State Secret',
        confidence: 'medium'
    },
    {
        name: 'Pulumi API Key',
        pattern: /(?:pulumi[_-]?api[_-]?key|pulumi[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Pulumi API Key',
        confidence: 'high'
    },
    {
        name: 'Pulumi Access Token',
        pattern: /pulumi-[a-zA-Z0-9\-_]{40,}/g,
        suggestion: 'Pulumi Access Token',
        confidence: 'high'
    },

    // ========== LANGUAGE-SPECIFIC PATTERNS ==========
    {
        name: 'Python os.environ Secret',
        pattern: /os\.environ\[["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["']\]\s*=\s*["']([^"']{10,})["']/gi,
        suggestion: 'Python Environment Secret',
        confidence: 'medium'
    },
    {
        name: 'Node.js process.env Secret',
        pattern: /process\.env\[["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["']\]\s*=\s*["']([^"']{10,})["']/gi,
        suggestion: 'Node.js Environment Secret',
        confidence: 'medium'
    },
    {
        name: 'Go os.Getenv Secret',
        pattern: /os\.Setenv\(["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["'],\s*["']([^"']{10,})["']\)/gi,
        suggestion: 'Go Environment Secret',
        confidence: 'medium'
    },
    {
        name: 'Java System.getenv Secret',
        pattern: /System\.setProperty\(["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["'],\s*["']([^"']{10,})["']\)/gi,
        suggestion: 'Java System Property Secret',
        confidence: 'medium'
    },
    {
        name: 'Ruby ENV Secret',
        pattern: /ENV\[["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["']\]\s*=\s*["']([^"']{10,})["']/gi,
        suggestion: 'Ruby Environment Secret',
        confidence: 'medium'
    },
    {
        name: 'PHP getenv Secret',
        pattern: /putenv\(["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))=["']([^"']{10,})["']\)/gi,
        suggestion: 'PHP Environment Secret',
        confidence: 'medium'
    },
    {
        name: 'C# Environment Variable Secret',
        pattern: /Environment\.SetEnvironmentVariable\(["']([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))["'],\s*["']([^"']{10,})["']\)/gi,
        suggestion: 'C# Environment Secret',
        confidence: 'medium'
    },

    // ========== CONFIGURATION FILE PATTERNS ==========
    {
        name: '.env File Secret',
        pattern: /^([A-Z_][A-Z0-9_]*[_-]?(?:SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY))\s*=\s*["']?([^"'\n]{10,})["']?$/gim,
        suggestion: '.env File Secret',
        confidence: 'medium'
    },
    {
        name: 'Docker Compose Secret',
        pattern: /(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*["']([^"']{8,})["']/gi,
        suggestion: 'Docker Compose Secret',
        confidence: 'high'
    },
    {
        name: 'Kubernetes Secret (expanded)',
        pattern: /(?:kubernetes[_-]?secret|k8s[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'Kubernetes Secret',
        confidence: 'medium'
    },
    {
        name: 'Kubernetes Base64 Secret',
        pattern: /kind:\s*Secret.*?data:.*?password:\s*([A-Za-z0-9+/=]{20,})/gs,
        suggestion: 'Kubernetes Base64 Secret',
        confidence: 'high'
    },
    {
        name: 'YAML Secret',
        pattern: /(?:secret|password|key|token|api[_-]?key):\s*["']?([A-Za-z0-9\-_./+=]{20,})["']?/gi,
        suggestion: 'YAML Secret',
        confidence: 'medium'
    },
    {
        name: 'JSON Secret',
        pattern: /"(?:secret|password|key|token|api[_-]?key)":\s*"([^"]{10,})"/gi,
        suggestion: 'JSON Secret',
        confidence: 'medium'
    },
    {
        name: 'XML Secret',
        pattern: /<(?:secret|password|key|token|api[_-]?key)>\s*([^<]{10,})\s*<\/(?:secret|password|key|token|api[_-]?key)>/gi,
        suggestion: 'XML Secret',
        confidence: 'medium'
    },
    {
        name: 'Properties File Secret',
        pattern: /^(?:secret|password|key|token|api[_-]?key)\s*[:=]\s*([^=\n]{10,})$/gim,
        suggestion: 'Properties File Secret',
        confidence: 'medium'
    },

    // ========== ADDITIONAL WEBHOOK PATTERNS ==========
    {
        name: 'GitHub Webhook Secret',
        pattern: /(?:github[_-]?webhook[_-]?secret|gh[_-]?webhook[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
        suggestion: 'GitHub Webhook Secret',
        confidence: 'high'
    },
    {
        name: 'GitLab Webhook Token',
        pattern: /(?:gitlab[_-]?webhook[_-]?token|gitlab[_-]?webhook)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
        suggestion: 'GitLab Webhook Token',
        confidence: 'high'
    },
    {
        name: 'Bitbucket Webhook Secret',
        pattern: /(?:bitbucket[_-]?webhook[_-]?secret|bitbucket[_-]?webhook)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
        suggestion: 'Bitbucket Webhook Secret',
        confidence: 'high'
    },
    {
        name: 'Stripe Webhook Secret',
        pattern: /(?:stripe[_-]?webhook[_-]?secret|stripe[_-]?webhook)\s*[:=]\s*["']?(whsec_[a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Stripe Webhook Secret',
        confidence: 'high'
    },
    {
        name: 'Stripe Webhook Signing Secret',
        pattern: /whsec_[a-zA-Z0-9]{32,}/g,
        suggestion: 'Stripe Webhook Signing Secret',
        confidence: 'high'
    },
    {
        name: 'Shopify Webhook Secret',
        pattern: /(?:shopify[_-]?webhook[_-]?secret|shopify[_-]?webhook)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Shopify Webhook Secret',
        confidence: 'high'
    },
    {
        name: 'PayPal Webhook Secret',
        pattern: /(?:paypal[_-]?webhook[_-]?secret|paypal[_-]?webhook)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'PayPal Webhook Secret',
        confidence: 'high'
    },

    // ========== ADDITIONAL SERVICE-SPECIFIC PATTERNS ==========
    {
        name: 'Vercel API Token',
        pattern: /(?:vercel[_-]?api[_-]?token|vercel[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Vercel API Token',
        confidence: 'high'
    },
    {
        name: 'Netlify API Token',
        pattern: /(?:netlify[_-]?api[_-]?token|netlify[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Netlify API Token',
        confidence: 'high'
    },
    {
        name: 'Railway API Token',
        pattern: /(?:railway[_-]?api[_-]?token|railway[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Railway API Token',
        confidence: 'high'
    },
    {
        name: 'Render API Key',
        pattern: /(?:render[_-]?api[_-]?key|render[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Render API Key',
        confidence: 'high'
    },
    {
        name: 'Fly.io API Token',
        pattern: /(?:fly[_-]?io[_-]?api[_-]?token|fly[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Fly.io API Token',
        confidence: 'high'
    },
    {
        name: 'DigitalOcean App Platform Token',
        pattern: /(?:digitalocean[_-]?app[_-]?platform[_-]?token|do[_-]?app[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'DigitalOcean App Platform Token',
        confidence: 'high'
    },
    {
        name: 'Airtable API Key',
        pattern: /(?:airtable[_-]?api[_-]?key|airtable[_-]?key)\s*[:=]\s*["']?(pat[a-zA-Z0-9\-_]{17})["']?/gi,
        suggestion: 'Airtable API Key',
        confidence: 'high'
    },
    {
        name: 'Airtable Personal Access Token',
        pattern: /pat[a-zA-Z0-9\-_]{17}/g,
        suggestion: 'Airtable Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'Notion API Key',
        pattern: /(?:notion[_-]?api[_-]?key|notion[_-]?key)\s*[:=]\s*["']?(secret_[a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Notion API Key',
        confidence: 'high'
    },
    {
        name: 'Notion Integration Token',
        pattern: /secret_[a-zA-Z0-9\-_]{32,}/g,
        suggestion: 'Notion Integration Token',
        confidence: 'high'
    },
    {
        name: 'Linear API Key',
        pattern: /(?:linear[_-]?api[_-]?key|linear[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Linear API Key',
        confidence: 'high'
    },
    {
        name: 'Asana API Key',
        pattern: /(?:asana[_-]?api[_-]?key|asana[_-]?key)\s*[:=]\s*["']?([0-9]{1,}\.[a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Asana API Key',
        confidence: 'high'
    },
    {
        name: 'Monday.com API Token',
        pattern: /(?:monday[_-]?com[_-]?api[_-]?token|monday[_-]?api[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Monday.com API Token',
        confidence: 'high'
    },
    {
        name: 'Trello API Key',
        pattern: /(?:trello[_-]?api[_-]?key|trello[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Trello API Key',
        confidence: 'high'
    },
    {
        name: 'Trello API Token',
        pattern: /(?:trello[_-]?api[_-]?token|trello[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{64,})["']?/gi,
        suggestion: 'Trello API Token',
        confidence: 'high'
    }
];
