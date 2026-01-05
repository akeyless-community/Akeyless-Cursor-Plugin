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
        pattern: /(?:elasticsearch|es):\/\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=\-]+/g,
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
        pattern: /(?:twilio[_-]?auth[_-]?token|twilio[_-]?token)\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?/gi,
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
    },

    // ========== ADDITIONAL PATTERNS - EXPANDED COVERAGE ==========
    
    // Additional Cloud Services
    {
        name: 'Cloudflare API Token (alternative format)',
        pattern: /(?:cloudflare[_-]?api[_-]?token|cf[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{37})["']?/gi,
        suggestion: 'Cloudflare API Token',
        confidence: 'high'
    },
    {
        name: 'AWS CodeCommit Credential',
        pattern: /(?:aws[_-]?codecommit[_-]?credential|codecommit[_-]?credential)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS CodeCommit Credential',
        confidence: 'high'
    },
    {
        name: 'AWS Elastic Beanstalk Token',
        pattern: /(?:aws[_-]?elastic[_-]?beanstalk[_-]?token|eb[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS Elastic Beanstalk Token',
        confidence: 'high'
    },
    {
        name: 'Azure AD Client Secret',
        pattern: /(?:azure[_-]?ad[_-]?client[_-]?secret|azuread[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/]{40,})["']?/gi,
        suggestion: 'Azure AD Client Secret',
        confidence: 'high'
    },
    {
        name: 'Azure AD Application Secret',
        pattern: /(?:azure[_-]?ad[_-]?application[_-]?secret|azuread[_-]?app[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/]{40,})["']?/gi,
        suggestion: 'Azure AD Application Secret',
        confidence: 'high'
    },
    {
        name: 'GCP OAuth Client ID',
        pattern: /(?:gcp[_-]?oauth[_-]?client[_-]?id|google[_-]?oauth[_-]?client[_-]?id)\s*[:=]\s*["']?([0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com)["']?/gi,
        suggestion: 'GCP OAuth Client ID',
        confidence: 'high'
    },
    {
        name: 'GCP OAuth Client Secret',
        pattern: /(?:gcp[_-]?oauth[_-]?client[_-]?secret|google[_-]?oauth[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{24,})["']?/gi,
        suggestion: 'GCP OAuth Client Secret',
        confidence: 'high'
    },

    // Additional Database Patterns
    {
        name: 'SQL Server Connection String',
        pattern: /(?:sql[_-]?server[_-]?connection|mssql[_-]?connection)\s*[:=]\s*["']?(Server=[^;]+;Database=[^;]+;User\s+Id=[^;]+;Password=[^;]+)["']?/gi,
        suggestion: 'SQL Server Connection String',
        confidence: 'high'
    },
    {
        name: 'Oracle Connection String',
        pattern: /(?:oracle[_-]?connection|oracle[_-]?connection[_-]?string)\s*[:=]\s*["']?(oracle:\/\/[^"']+)["']?/gi,
        suggestion: 'Oracle Connection String',
        confidence: 'high'
    },
    {
        name: 'SQLite Database Path',
        pattern: /(?:sqlite[_-]?database|sqlite[_-]?db)\s*[:=]\s*["']?([^"']+\.db)["']?/gi,
        suggestion: 'SQLite Database Path',
        confidence: 'medium'
    },
    {
        name: 'MariaDB Connection String',
        pattern: /(?:mariadb[_-]?connection|mariadb[_-]?connection[_-]?string)\s*[:=]\s*["']?(mariadb:\/\/[^"']+)["']?/gi,
        suggestion: 'MariaDB Connection String',
        confidence: 'high'
    },
    {
        name: 'Cassandra Password',
        pattern: /(?:cassandra[_-]?password|cassandra[_-]?pass)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Cassandra Password',
        confidence: 'medium'
    },

    // Additional Email Services
    {
        name: 'Amazon SES Access Key',
        pattern: /(?:amazon[_-]?ses[_-]?access[_-]?key|ses[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'Amazon SES Access Key',
        confidence: 'high'
    },
    {
        name: 'Amazon SES Secret Key',
        pattern: /(?:amazon[_-]?ses[_-]?secret[_-]?key|ses[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{40})["']?/gi,
        suggestion: 'Amazon SES Secret Key',
        confidence: 'high'
    },
    {
        name: 'Postmark Server API Token',
        pattern: /(?:postmark[_-]?server[_-]?api[_-]?token|postmark[_-]?server[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
        suggestion: 'Postmark Server API Token',
        confidence: 'high'
    },
    {
        name: 'SparkPost API Key (alternative)',
        pattern: /(?:sparkpost[_-]?api[_-]?key|sparkpost[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{64,})["']?/gi,
        suggestion: 'SparkPost API Key',
        confidence: 'high'
    },
    {
        name: 'Mailgun Domain API Key',
        pattern: /(?:mailgun[_-]?domain[_-]?api[_-]?key|mailgun[_-]?domain[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Mailgun Domain API Key',
        confidence: 'high'
    },
    {
        name: 'SendGrid API Key (alternative)',
        pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
        suggestion: 'SendGrid API Key',
        confidence: 'high'
    },

    // Additional Social Media & Marketing
    {
        name: 'Facebook Access Token (alternative)',
        pattern: /EAAB[a-zA-Z0-9]{100,}/g,
        suggestion: 'Facebook Access Token',
        confidence: 'high'
    },
    {
        name: 'Instagram Basic Display API Token',
        pattern: /(?:instagram[_-]?basic[_-]?display[_-]?api[_-]?token|ig[_-]?basic[_-]?display[_-]?token)\s*[:=]\s*["']?([0-9]{10,}\.[a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Instagram Basic Display API Token',
        confidence: 'high'
    },
    {
        name: 'TikTok Access Token',
        pattern: /(?:tiktok[_-]?access[_-]?token|tiktok[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'TikTok Access Token',
        confidence: 'high'
    },
    {
        name: 'Snapchat API Key',
        pattern: /(?:snapchat[_-]?api[_-]?key|snapchat[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Snapchat API Key',
        confidence: 'high'
    },
    {
        name: 'YouTube API Key',
        pattern: /(?:youtube[_-]?api[_-]?key|yt[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'YouTube API Key',
        confidence: 'high'
    },
    {
        name: 'Vimeo Access Token',
        pattern: /(?:vimeo[_-]?access[_-]?token|vimeo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Vimeo Access Token',
        confidence: 'high'
    },

    // Additional Payment & E-commerce
    {
        name: 'WooCommerce API Key',
        pattern: /(?:woocommerce[_-]?api[_-]?key|wc[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'WooCommerce API Key',
        confidence: 'high'
    },
    {
        name: 'WooCommerce Secret',
        pattern: /(?:woocommerce[_-]?secret|wc[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'WooCommerce Secret',
        confidence: 'high'
    },
    {
        name: 'BigCommerce API Token',
        pattern: /(?:bigcommerce[_-]?api[_-]?token|bigcommerce[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'BigCommerce API Token',
        confidence: 'high'
    },
    {
        name: 'Magento Access Token',
        pattern: /(?:magento[_-]?access[_-]?token|magento[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Magento Access Token',
        confidence: 'high'
    },
    {
        name: 'PrestaShop API Key',
        pattern: /(?:prestashop[_-]?api[_-]?key|prestashop[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'PrestaShop API Key',
        confidence: 'high'
    },
    {
        name: 'Square Application ID',
        pattern: /(?:square[_-]?application[_-]?id|square[_-]?app[_-]?id)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Square Application ID',
        confidence: 'high'
    },

    // Additional Development Tools
    {
        name: 'JetBrains Space API Token',
        pattern: /(?:jetbrains[_-]?space[_-]?api[_-]?token|space[_-]?api[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'JetBrains Space API Token',
        confidence: 'high'
    },
    {
        name: 'JetBrains YouTrack Token',
        pattern: /(?:jetbrains[_-]?youtrack[_-]?token|youtrack[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'JetBrains YouTrack Token',
        confidence: 'high'
    },
    {
        name: 'SonarQube Token',
        pattern: /(?:sonarqube[_-]?token|sonar[_-]?token)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'SonarQube Token',
        confidence: 'high'
    },
    {
        name: 'CodeClimate API Token',
        pattern: /(?:codeclimate[_-]?api[_-]?token|codeclimate[_-]?token)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'CodeClimate API Token',
        confidence: 'high'
    },
    {
        name: 'Coveralls API Token',
        pattern: /(?:coveralls[_-]?api[_-]?token|coveralls[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Coveralls API Token',
        confidence: 'high'
    },
    {
        name: 'Codacy API Token',
        pattern: /(?:codacy[_-]?api[_-]?token|codacy[_-]?token)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Codacy API Token',
        confidence: 'high'
    },

    // Additional Infrastructure & DevOps
    {
        name: 'Docker Hub Password',
        pattern: /(?:docker[_-]?hub[_-]?password|dockerhub[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Docker Hub Password',
        confidence: 'medium'
    },
    {
        name: 'Docker Registry Auth Token',
        pattern: /(?:docker[_-]?registry[_-]?auth[_-]?token|docker[_-]?registry[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'Docker Registry Auth Token',
        confidence: 'high'
    },
    {
        name: 'HashiCorp Vault Token',
        pattern: /(?:hashicorp[_-]?vault[_-]?token|vault[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'HashiCorp Vault Token',
        confidence: 'high'
    },
    {
        name: 'Consul ACL Token',
        pattern: /(?:consul[_-]?acl[_-]?token|consul[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{36})["']?/gi,
        suggestion: 'Consul ACL Token',
        confidence: 'high'
    },
    {
        name: 'Nomad Token',
        pattern: /(?:nomad[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{36})["']?/gi,
        suggestion: 'Nomad Token',
        confidence: 'high'
    },
    {
        name: 'Nomad Secret ID',
        pattern: /(?:nomad[_-]?secret[_-]?id)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{36})["']?/gi,
        suggestion: 'Nomad Secret ID',
        confidence: 'high'
    },

    // Additional Messaging Services
    {
        name: 'Microsoft Teams Bot Token',
        pattern: /(?:microsoft[_-]?teams[_-]?bot[_-]?token|teams[_-]?bot[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Microsoft Teams Bot Token',
        confidence: 'high'
    },
    {
        name: 'Zoom API Key',
        pattern: /(?:zoom[_-]?api[_-]?key|zoom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Zoom API Key',
        confidence: 'high'
    },
    {
        name: 'Zoom API Secret',
        pattern: /(?:zoom[_-]?api[_-]?secret|zoom[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Zoom API Secret',
        confidence: 'high'
    },
    {
        name: 'Microsoft Teams App Secret',
        pattern: /(?:microsoft[_-]?teams[_-]?app[_-]?secret|teams[_-]?app[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Microsoft Teams App Secret',
        confidence: 'high'
    },

    // Additional Content & Media Services
    {
        name: 'Cloudinary Cloud Name',
        pattern: /(?:cloudinary[_-]?cloud[_-]?name|cloudinary[_-]?name)\s*[:=]\s*["']?([a-z0-9]+)["']?/gi,
        suggestion: 'Cloudinary Cloud Name',
        confidence: 'medium'
    },
    {
        name: 'Cloudinary API Secret (expanded)',
        pattern: /(?:cloudinary[_-]?api[_-]?secret|cloudinary[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Cloudinary API Secret',
        confidence: 'high'
    },
    {
        name: 'Imgur Client ID',
        pattern: /(?:imgur[_-]?client[_-]?id|imgur[_-]?id)\s*[:=]\s*["']?([a-zA-Z0-9]{56})["']?/gi,
        suggestion: 'Imgur Client ID',
        confidence: 'high'
    },
    {
        name: 'Imgur Client Secret',
        pattern: /(?:imgur[_-]?client[_-]?secret|imgur[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40})["']?/gi,
        suggestion: 'Imgur Client Secret',
        confidence: 'high'
    },
    {
        name: 'Unsplash Access Key',
        pattern: /(?:unsplash[_-]?access[_-]?key|unsplash[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{43})["']?/gi,
        suggestion: 'Unsplash Access Key',
        confidence: 'high'
    },
    {
        name: 'Pexels API Key',
        pattern: /(?:pexels[_-]?api[_-]?key|pexels[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{56})["']?/gi,
        suggestion: 'Pexels API Key',
        confidence: 'high'
    },

    // Additional Obfuscated/Encoded Patterns
    {
        name: 'Base64 Encoded Secret',
        pattern: /(?:secret|key|token|password|auth)[\s:=]+["']?([A-Za-z0-9+/]{50,}={0,2})["']?/gi,
        suggestion: 'Base64 Encoded Secret',
        confidence: 'medium'
    },
    {
        name: 'Hex Encoded Secret',
        pattern: /(?:secret|key|token|password|auth)[\s:=]+["']?([a-f0-9]{40,})["']?/gi,
        suggestion: 'Hex Encoded Secret',
        confidence: 'medium'
    },
    {
        name: 'URL Encoded Secret',
        pattern: /(?:secret|key|token|password|auth)[\s:=]+["']?([%0-9A-Fa-f]{40,})["']?/gi,
        suggestion: 'URL Encoded Secret',
        confidence: 'medium'
    },
    {
        name: 'Obfuscated Password',
        pattern: /(?:password|passwd|pwd)[\s:=]+["']?([A-Za-z0-9+/=]{20,})["']?/gi,
        suggestion: 'Obfuscated Password',
        confidence: 'medium'
    },

    // Additional Regional Services
    {
        name: 'Alipay App ID',
        pattern: /(?:alipay[_-]?app[_-]?id|alipay[_-]?id)\s*[:=]\s*["']?([0-9]{16})["']?/gi,
        suggestion: 'Alipay App ID',
        confidence: 'high'
    },
    {
        name: 'Alipay Private Key',
        pattern: /(?:alipay[_-]?private[_-]?key|alipay[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{100,})["']?/gi,
        suggestion: 'Alipay Private Key',
        confidence: 'high'
    },
    {
        name: 'WeChat Pay API Key',
        pattern: /(?:wechat[_-]?pay[_-]?api[_-]?key|wechatpay[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'WeChat Pay API Key',
        confidence: 'high'
    },
    {
        name: 'Razorpay Key ID',
        pattern: /(?:razorpay[_-]?key[_-]?id|rzp[_-]?key[_-]?id)\s*[:=]\s*["']?(rzp_[a-zA-Z0-9]{14})["']?/gi,
        suggestion: 'Razorpay Key ID',
        confidence: 'high'
    },
    {
        name: 'Razorpay Key Secret',
        pattern: /(?:razorpay[_-]?key[_-]?secret|rzp[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Razorpay Key Secret',
        confidence: 'high'
    },

    // Additional Testing & QA Tools
    {
        name: 'BrowserStack Access Key',
        pattern: /(?:browserstack[_-]?access[_-]?key|browserstack[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20})["']?/gi,
        suggestion: 'BrowserStack Access Key',
        confidence: 'high'
    },
    {
        name: 'Sauce Labs Access Key',
        pattern: /(?:saucelabs[_-]?access[_-]?key|saucelabs[_-]?key)\s*[:=]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
        suggestion: 'Sauce Labs Access Key',
        confidence: 'high'
    },
    {
        name: 'LambdaTest Access Key',
        pattern: /(?:lambdatest[_-]?access[_-]?key|lambdatest[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'LambdaTest Access Key',
        confidence: 'high'
    },
    {
        name: 'TestRail API Key',
        pattern: /(?:testrail[_-]?api[_-]?key|testrail[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'TestRail API Key',
        confidence: 'high'
    },

    // Additional Analytics & Tracking
    {
        name: 'Google Tag Manager API Key',
        pattern: /(?:google[_-]?tag[_-]?manager[_-]?api[_-]?key|gtm[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{32,})["']?/gi,
        suggestion: 'Google Tag Manager API Key',
        confidence: 'high'
    },
    {
        name: 'Adobe Analytics API Key',
        pattern: /(?:adobe[_-]?analytics[_-]?api[_-]?key|adobe[_-]?analytics[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Adobe Analytics API Key',
        confidence: 'high'
    },
    {
        name: 'Adobe IMS Access Token',
        pattern: /(?:adobe[_-]?ims[_-]?access[_-]?token|adobe[_-]?ims[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{100,})["']?/gi,
        suggestion: 'Adobe IMS Access Token',
        confidence: 'high'
    },
    {
        name: 'Adobe Creative SDK Client Secret',
        pattern: /(?:adobe[_-]?creative[_-]?sdk[_-]?client[_-]?secret|adobe[_-]?creative[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Adobe Creative SDK Client Secret',
        confidence: 'high'
    },

    // ========== ADDITIONAL PATTERNS - FURTHER EXPANSION ==========
    
    // Additional Cloud & Infrastructure
    {
        name: 'AWS CodeDeploy Access Key',
        pattern: /(?:aws[_-]?codedeploy[_-]?access[_-]?key|codedeploy[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
        suggestion: 'AWS CodeDeploy Access Key',
        confidence: 'high'
    },
    {
        name: 'AWS CodePipeline Token',
        pattern: /(?:aws[_-]?codepipeline[_-]?token|codepipeline[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS CodePipeline Token',
        confidence: 'high'
    },
    {
        name: 'AWS Lambda Function Secret',
        pattern: /(?:aws[_-]?lambda[_-]?function[_-]?secret|lambda[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS Lambda Function Secret',
        confidence: 'high'
    },
    {
        name: 'AWS ECS Task Secret',
        pattern: /(?:aws[_-]?ecs[_-]?task[_-]?secret|ecs[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS ECS Task Secret',
        confidence: 'high'
    },
    {
        name: 'AWS EKS Cluster Secret',
        pattern: /(?:aws[_-]?eks[_-]?cluster[_-]?secret|eks[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS EKS Cluster Secret',
        confidence: 'high'
    },
    {
        name: 'Azure Key Vault Secret',
        pattern: /(?:azure[_-]?key[_-]?vault[_-]?secret|keyvault[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        suggestion: 'Azure Key Vault Secret',
        confidence: 'high'
    },
    {
        name: 'Azure Container Registry Password',
        pattern: /(?:azure[_-]?container[_-]?registry[_-]?password|acr[_-]?password)\s*[:=]\s*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        suggestion: 'Azure Container Registry Password',
        confidence: 'high'
    },
    {
        name: 'GCP Cloud SQL Password',
        pattern: /(?:gcp[_-]?cloud[_-]?sql[_-]?password|cloudsql[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'GCP Cloud SQL Password',
        confidence: 'high'
    },
    {
        name: 'GCP Cloud Storage Key',
        pattern: /(?:gcp[_-]?cloud[_-]?storage[_-]?key|gcs[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'GCP Cloud Storage Key',
        confidence: 'high'
    },
    {
        name: 'DigitalOcean Spaces Secret Key',
        pattern: /(?:digitalocean[_-]?spaces[_-]?secret[_-]?key|do[_-]?spaces[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        suggestion: 'DigitalOcean Spaces Secret Key',
        confidence: 'high'
    },

    // Additional Database & Data Services
    {
        name: 'Snowflake Account Password',
        pattern: /(?:snowflake[_-]?account[_-]?password|snowflake[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
        suggestion: 'Snowflake Account Password',
        confidence: 'high'
    },
    {
        name: 'Snowflake Private Key',
        pattern: /(?:snowflake[_-]?private[_-]?key|snowflake[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{100,})["']?/gi,
        suggestion: 'Snowflake Private Key',
        confidence: 'high'
    },
    {
        name: 'BigQuery Service Account Key',
        pattern: /(?:bigquery[_-]?service[_-]?account[_-]?key|bigquery[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'BigQuery Service Account Key',
        confidence: 'high'
    },
    {
        name: 'Databricks Personal Access Token',
        pattern: /(?:databricks[_-]?personal[_-]?access[_-]?token|databricks[_-]?pat)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Databricks Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'Databricks Token',
        pattern: /dapi[a-zA-Z0-9\-_]{32,}/g,
        suggestion: 'Databricks Token',
        confidence: 'high'
    },
    {
        name: 'Tableau Personal Access Token',
        pattern: /(?:tableau[_-]?personal[_-]?access[_-]?token|tableau[_-]?pat)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Tableau Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'Power BI API Key',
        pattern: /(?:power[_-]?bi[_-]?api[_-]?key|powerbi[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Power BI API Key',
        confidence: 'high'
    },
    {
        name: 'MongoDB Atlas API Key',
        pattern: /(?:mongodb[_-]?atlas[_-]?api[_-]?key|atlas[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'MongoDB Atlas API Key',
        confidence: 'high'
    },
    {
        name: 'Redis Labs API Key',
        pattern: /(?:redis[_-]?labs[_-]?api[_-]?key|redislabs[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Redis Labs API Key',
        confidence: 'high'
    },
    {
        name: 'Elastic Cloud API Key',
        pattern: /(?:elastic[_-]?cloud[_-]?api[_-]?key|elasticcloud[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Elastic Cloud API Key',
        confidence: 'high'
    },

    // Additional SaaS & Productivity Tools
    {
        name: 'ClickUp API Token',
        pattern: /(?:clickup[_-]?api[_-]?token|clickup[_-]?token)\s*[:=]\s*["']?(pk_[a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'ClickUp API Token',
        confidence: 'high'
    },
    {
        name: 'ClickUp Token',
        pattern: /pk_[a-zA-Z0-9\-_]{40,}/g,
        suggestion: 'ClickUp Token',
        confidence: 'high'
    },
    {
        name: 'Wrike API Token',
        pattern: /(?:wrike[_-]?api[_-]?token|wrike[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Wrike API Token',
        confidence: 'high'
    },
    {
        name: 'Smartsheet Access Token',
        pattern: /(?:smartsheet[_-]?access[_-]?token|smartsheet[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Smartsheet Access Token',
        confidence: 'high'
    },
    {
        name: 'Airtable Personal Access Token (expanded)',
        pattern: /pat[a-zA-Z0-9\-_]{17}/g,
        suggestion: 'Airtable Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'Notion Integration Token (expanded)',
        pattern: /secret_[a-zA-Z0-9\-_]{32,}/g,
        suggestion: 'Notion Integration Token',
        confidence: 'high'
    },
    {
        name: 'Coda API Token',
        pattern: /(?:coda[_-]?api[_-]?token|coda[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Coda API Token',
        confidence: 'high'
    },
    {
        name: 'Roam Research API Key',
        pattern: /(?:roam[_-]?research[_-]?api[_-]?key|roam[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Roam Research API Key',
        confidence: 'high'
    },
    {
        name: 'Obsidian API Key',
        pattern: /(?:obsidian[_-]?api[_-]?key|obsidian[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Obsidian API Key',
        confidence: 'high'
    },
    {
        name: 'Evernote API Token',
        pattern: /(?:evernote[_-]?api[_-]?token|evernote[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Evernote API Token',
        confidence: 'high'
    },

    // Additional Communication & Collaboration
    {
        name: 'Microsoft Graph API Secret',
        pattern: /(?:microsoft[_-]?graph[_-]?api[_-]?secret|graph[_-]?api[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Microsoft Graph API Secret',
        confidence: 'high'
    },
    {
        name: 'Microsoft 365 Client Secret',
        pattern: /(?:microsoft[_-]?365[_-]?client[_-]?secret|m365[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Microsoft 365 Client Secret',
        confidence: 'high'
    },
    {
        name: 'Google Workspace API Key',
        pattern: /(?:google[_-]?workspace[_-]?api[_-]?key|workspace[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Workspace API Key',
        confidence: 'high'
    },
    {
        name: 'Google Workspace Client Secret',
        pattern: /(?:google[_-]?workspace[_-]?client[_-]?secret|workspace[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{24,})["']?/gi,
        suggestion: 'Google Workspace Client Secret',
        confidence: 'high'
    },
    {
        name: 'Slack App Secret',
        pattern: /(?:slack[_-]?app[_-]?secret|slack[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Slack App Secret',
        confidence: 'high'
    },
    {
        name: 'Discord Client Secret',
        pattern: /(?:discord[_-]?client[_-]?secret|discord[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32})["']?/gi,
        suggestion: 'Discord Client Secret',
        confidence: 'high'
    },
    {
        name: 'Telegram Bot API Token (expanded)',
        pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
        suggestion: 'Telegram Bot API Token',
        confidence: 'high'
    },
    {
        name: 'WhatsApp Business API Token',
        pattern: /(?:whatsapp[_-]?business[_-]?api[_-]?token|whatsapp[_-]?api[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'WhatsApp Business API Token',
        confidence: 'high'
    },
    {
        name: 'Line Channel Secret',
        pattern: /(?:line[_-]?channel[_-]?secret|line[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Line Channel Secret',
        confidence: 'high'
    },
    {
        name: 'WeChat App Secret',
        pattern: /(?:wechat[_-]?app[_-]?secret|wechat[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32})["']?/gi,
        suggestion: 'WeChat App Secret',
        confidence: 'high'
    },

    // Additional AI & ML Services
    {
        name: 'Google AI Studio API Key',
        pattern: /(?:google[_-]?ai[_-]?studio[_-]?api[_-]?key|aistudio[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google AI Studio API Key',
        confidence: 'high'
    },
    {
        name: 'Google Vertex AI API Key',
        pattern: /(?:google[_-]?vertex[_-]?ai[_-]?api[_-]?key|vertex[_-]?ai[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Vertex AI API Key',
        confidence: 'high'
    },
    {
        name: 'Azure OpenAI API Key',
        pattern: /(?:azure[_-]?openai[_-]?api[_-]?key|azure[_-]?openai[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Azure OpenAI API Key',
        confidence: 'high'
    },
    {
        name: 'AWS Bedrock API Key',
        pattern: /(?:aws[_-]?bedrock[_-]?api[_-]?key|bedrock[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS Bedrock API Key',
        confidence: 'high'
    },
    {
        name: 'Anthropic Claude API Key (alternative)',
        pattern: /(?:anthropic[_-]?claude[_-]?api[_-]?key|claude[_-]?api[_-]?key)\s*[:=]\s*["']?(sk-ant-[A-Za-z0-9\-_]{95,})["']?/gi,
        suggestion: 'Anthropic Claude API Key',
        confidence: 'high'
    },
    {
        name: 'Cohere API Key (expanded)',
        pattern: /(?:cohere[_-]?api[_-]?key|cohere[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Cohere API Key',
        confidence: 'high'
    },
    {
        name: 'Hugging Face API Token (expanded)',
        pattern: /hf_[a-zA-Z0-9]{37}/g,
        suggestion: 'Hugging Face API Token',
        confidence: 'high'
    },
    {
        name: 'Replicate API Token (expanded)',
        pattern: /r8_[a-zA-Z0-9\-_]{37,}/g,
        suggestion: 'Replicate API Token',
        confidence: 'high'
    },
    {
        name: 'Stability AI API Key (expanded)',
        pattern: /(?:stability[_-]?ai[_-]?api[_-]?key|stability[_-]?api[_-]?key)\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{48,})["']?/gi,
        suggestion: 'Stability AI API Key',
        confidence: 'high'
    },
    {
        name: 'Jasper AI API Key',
        pattern: /(?:jasper[_-]?ai[_-]?api[_-]?key|jasper[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Jasper AI API Key',
        confidence: 'high'
    },
    {
        name: 'Copy.ai API Key',
        pattern: /(?:copy[_-]?ai[_-]?api[_-]?key|copyai[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Copy.ai API Key',
        confidence: 'high'
    },
    {
        name: 'Writesonic API Key',
        pattern: /(?:writesonic[_-]?api[_-]?key|writesonic[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Writesonic API Key',
        confidence: 'high'
    },

    // Additional Payment & Financial Services
    {
        name: 'Square Access Token (expanded)',
        pattern: /EAAA[a-zA-Z0-9]{60,}/g,
        suggestion: 'Square Access Token',
        confidence: 'high'
    },
    {
        name: 'PayPal Client ID (expanded)',
        pattern: /(?:paypal[_-]?client[_-]?id|paypal[_-]?id)\s*[:=]\s*["']?([A-Za-z0-9]{80,})["']?/gi,
        suggestion: 'PayPal Client ID',
        confidence: 'high'
    },
    {
        name: 'Stripe Connect Client Secret',
        pattern: /(?:stripe[_-]?connect[_-]?client[_-]?secret|stripe[_-]?connect[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Stripe Connect Client Secret',
        confidence: 'high'
    },
    {
        name: 'Braintree Merchant ID',
        pattern: /(?:braintree[_-]?merchant[_-]?id|braintree[_-]?merchant)\s*[:=]\s*["']?([a-zA-Z0-9]{16})["']?/gi,
        suggestion: 'Braintree Merchant ID',
        confidence: 'high'
    },
    {
        name: 'Braintree Private Key',
        pattern: /(?:braintree[_-]?private[_-]?key|braintree[_-]?private)\s*[:=]\s*["']?([A-Za-z0-9+/=]{100,})["']?/gi,
        suggestion: 'Braintree Private Key',
        confidence: 'high'
    },
    {
        name: 'Authorize.net Transaction Key',
        pattern: /(?:authorize[_-]?net[_-]?transaction[_-]?key|authnet[_-]?transaction[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
        suggestion: 'Authorize.net Transaction Key',
        confidence: 'high'
    },
    {
        name: 'Adyen Merchant Account',
        pattern: /(?:adyen[_-]?merchant[_-]?account|adyen[_-]?merchant)\s*[:=]\s*["']?([A-Za-z0-9]{8,})["']?/gi,
        suggestion: 'Adyen Merchant Account',
        confidence: 'high'
    },
    {
        name: 'Worldpay API Key',
        pattern: /(?:worldpay[_-]?api[_-]?key|worldpay[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Worldpay API Key',
        confidence: 'high'
    },
    {
        name: 'PayU API Key',
        pattern: /(?:payu[_-]?api[_-]?key|payu[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'PayU API Key',
        confidence: 'high'
    },
    {
        name: '2Checkout API Secret',
        pattern: /(?:2checkout[_-]?api[_-]?secret|2co[_-]?api[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: '2Checkout API Secret',
        confidence: 'high'
    },

    // Additional Monitoring & Logging
    {
        name: 'Datadog API Key (expanded)',
        pattern: /(?:datadog[_-]?api[_-]?key|datadog[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
        suggestion: 'Datadog API Key',
        confidence: 'high'
    },
    {
        name: 'Datadog Application Key (expanded)',
        pattern: /(?:datadog[_-]?application[_-]?key|datadog[_-]?app[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
        suggestion: 'Datadog Application Key',
        confidence: 'high'
    },
    {
        name: 'New Relic API Key (expanded)',
        pattern: /(?:newrelic[_-]?api[_-]?key|new[_-]?relic[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'New Relic API Key',
        confidence: 'high'
    },
    {
        name: 'New Relic License Key',
        pattern: /(?:newrelic[_-]?license[_-]?key|new[_-]?relic[_-]?license)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'New Relic License Key',
        confidence: 'high'
    },
    {
        name: 'Splunk API Token',
        pattern: /(?:splunk[_-]?api[_-]?token|splunk[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Splunk API Token',
        confidence: 'high'
    },
    {
        name: 'Loggly API Token',
        pattern: /(?:loggly[_-]?api[_-]?token|loggly[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Loggly API Token',
        confidence: 'high'
    },
    {
        name: 'Papertrail API Token',
        pattern: /(?:papertrail[_-]?api[_-]?token|papertrail[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Papertrail API Token',
        confidence: 'high'
    },
    {
        name: 'LogDNA API Key',
        pattern: /(?:logdna[_-]?api[_-]?key|logdna[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'LogDNA API Key',
        confidence: 'high'
    },
    {
        name: 'Sumo Logic Access ID',
        pattern: /(?:sumo[_-]?logic[_-]?access[_-]?id|sumologic[_-]?access[_-]?id)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
        suggestion: 'Sumo Logic Access ID',
        confidence: 'high'
    },
    {
        name: 'Sumo Logic Access Key',
        pattern: /(?:sumo[_-]?logic[_-]?access[_-]?key|sumologic[_-]?access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Sumo Logic Access Key',
        confidence: 'high'
    },

    // Additional Security & Identity
    {
        name: 'Auth0 Client Secret (expanded)',
        pattern: /(?:auth0[_-]?client[_-]?secret|auth0[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Auth0 Client Secret',
        confidence: 'high'
    },
    {
        name: 'Okta Client Secret',
        pattern: /(?:okta[_-]?client[_-]?secret|okta[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
        suggestion: 'Okta Client Secret',
        confidence: 'high'
    },
    {
        name: 'Ping Identity OAuth Client Secret',
        pattern: /(?:ping[_-]?identity[_-]?oauth[_-]?client[_-]?secret|ping[_-]?oauth[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Ping Identity OAuth Client Secret',
        confidence: 'high'
    },
    {
        name: 'ForgeRock Access Token (expanded)',
        pattern: /(?:forgerock[_-]?access[_-]?token|forgerock[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'ForgeRock Access Token',
        confidence: 'high'
    },
    {
        name: 'Keycloak Client Secret (expanded)',
        pattern: /(?:keycloak[_-]?client[_-]?secret|keycloak[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Keycloak Client Secret',
        confidence: 'high'
    },
    {
        name: 'CyberArk API Key',
        pattern: /(?:cyberark[_-]?api[_-]?key|cyberark[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'CyberArk API Key',
        confidence: 'high'
    },
    {
        name: 'Thycotic Secret Server Token',
        pattern: /(?:thycotic[_-]?secret[_-]?server[_-]?token|thycotic[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Thycotic Secret Server Token',
        confidence: 'high'
    },
    {
        name: '1Password Connect Token',
        pattern: /(?:1password[_-]?connect[_-]?token|op[_-]?connect[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: '1Password Connect Token',
        confidence: 'high'
    },
    {
        name: 'LastPass API Key',
        pattern: /(?:lastpass[_-]?api[_-]?key|lastpass[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'LastPass API Key',
        confidence: 'high'
    },
    {
        name: 'Dashlane API Key',
        pattern: /(?:dashlane[_-]?api[_-]?key|dashlane[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Dashlane API Key',
        confidence: 'high'
    },

    // ========== ADDITIONAL PATTERNS - COMPREHENSIVE EXPANSION ==========
    
    // Additional Cloud Edge Cases
    {
        name: 'AWS CloudFormation Stack Secret',
        pattern: /(?:aws[_-]?cloudformation[_-]?stack[_-]?secret|cfn[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS CloudFormation Stack Secret',
        confidence: 'high'
    },
    {
        name: 'AWS Systems Manager Parameter',
        pattern: /(?:aws[_-]?systems[_-]?manager[_-]?parameter|ssm[_-]?parameter)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS Systems Manager Parameter',
        confidence: 'high'
    },
    {
        name: 'AWS Secrets Manager Secret',
        pattern: /(?:aws[_-]?secrets[_-]?manager[_-]?secret|secretsmanager[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'AWS Secrets Manager Secret',
        confidence: 'high'
    },
    {
        name: 'Azure App Service Publishing Password',
        pattern: /(?:azure[_-]?app[_-]?service[_-]?publishing[_-]?password|azure[_-]?publishing[_-]?password)\s*[:=]\s*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        suggestion: 'Azure App Service Publishing Password',
        confidence: 'high'
    },
    {
        name: 'Azure DevOps Service Connection',
        pattern: /(?:azure[_-]?devops[_-]?service[_-]?connection|azdo[_-]?service[_-]?connection)\s*[:=]\s*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        suggestion: 'Azure DevOps Service Connection',
        confidence: 'high'
    },
    {
        name: 'GCP Cloud Build Service Account',
        pattern: /(?:gcp[_-]?cloud[_-]?build[_-]?service[_-]?account|cloudbuild[_-]?service[_-]?account)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'GCP Cloud Build Service Account',
        confidence: 'high'
    },
    {
        name: 'GCP Cloud Functions Secret',
        pattern: /(?:gcp[_-]?cloud[_-]?functions[_-]?secret|cloudfunctions[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
        suggestion: 'GCP Cloud Functions Secret',
        confidence: 'high'
    },
    {
        name: 'Alibaba Cloud Access Key Secret',
        pattern: /(?:alibaba[_-]?cloud[_-]?access[_-]?key[_-]?secret|aliyun[_-]?access[_-]?key[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{30,})["']?/gi,
        suggestion: 'Alibaba Cloud Access Key Secret',
        confidence: 'high'
    },
    {
        name: 'Tencent Cloud API Secret Key',
        pattern: /(?:tencent[_-]?cloud[_-]?api[_-]?secret[_-]?key|qcloud[_-]?api[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Tencent Cloud API Secret Key',
        confidence: 'high'
    },
    {
        name: 'Huawei Cloud Access Key',
        pattern: /(?:huawei[_-]?cloud[_-]?access[_-]?key|huaweicloud[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
        suggestion: 'Huawei Cloud Access Key',
        confidence: 'high'
    },

    // Additional Specialized Services
    {
        name: 'Figma Personal Access Token',
        pattern: /(?:figma[_-]?personal[_-]?access[_-]?token|figma[_-]?pat)\s*[:=]\s*["']?(figd_[a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Figma Personal Access Token',
        confidence: 'high'
    },
    {
        name: 'Figma Token',
        pattern: /figd_[a-zA-Z0-9\-_]{40,}/g,
        suggestion: 'Figma Token',
        confidence: 'high'
    },
    {
        name: 'Sketch API Token',
        pattern: /(?:sketch[_-]?api[_-]?token|sketch[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Sketch API Token',
        confidence: 'high'
    },
    {
        name: 'InVision API Token',
        pattern: /(?:invision[_-]?api[_-]?token|invision[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'InVision API Token',
        confidence: 'high'
    },
    {
        name: 'Marvel API Key',
        pattern: /(?:marvel[_-]?api[_-]?key|marvel[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Marvel API Key',
        confidence: 'high'
    },
    {
        name: 'Zeplin API Token',
        pattern: /(?:zeplin[_-]?api[_-]?token|zeplin[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Zeplin API Token',
        confidence: 'high'
    },
    {
        name: 'Abstract API Token',
        pattern: /(?:abstract[_-]?api[_-]?token|abstract[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Abstract API Token',
        confidence: 'high'
    },
    {
        name: 'Framer API Key',
        pattern: /(?:framer[_-]?api[_-]?key|framer[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Framer API Key',
        confidence: 'high'
    },
    {
        name: 'Webflow API Token',
        pattern: /(?:webflow[_-]?api[_-]?token|webflow[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Webflow API Token',
        confidence: 'high'
    },
    {
        name: 'Bubble API Key',
        pattern: /(?:bubble[_-]?api[_-]?key|bubble[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Bubble API Key',
        confidence: 'high'
    },

    // Additional Video & Streaming Services
    {
        name: 'Vimeo API Token',
        pattern: /(?:vimeo[_-]?api[_-]?token|vimeo[_-]?api)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Vimeo API Token',
        confidence: 'high'
    },
    {
        name: 'YouTube Data API Key',
        pattern: /(?:youtube[_-]?data[_-]?api[_-]?key|youtube[_-]?data[_-]?api)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'YouTube Data API Key',
        confidence: 'high'
    },
    {
        name: 'Twitch Client Secret',
        pattern: /(?:twitch[_-]?client[_-]?secret|twitch[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32})["']?/gi,
        suggestion: 'Twitch Client Secret',
        confidence: 'high'
    },
    {
        name: 'Streamlabs API Key',
        pattern: /(?:streamlabs[_-]?api[_-]?key|streamlabs[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Streamlabs API Key',
        confidence: 'high'
    },
    {
        name: 'Mux API Token',
        pattern: /(?:mux[_-]?api[_-]?token|mux[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Mux API Token',
        confidence: 'high'
    },
    {
        name: 'Cloudflare Stream API Token',
        pattern: /(?:cloudflare[_-]?stream[_-]?api[_-]?token|cf[_-]?stream[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Cloudflare Stream API Token',
        confidence: 'high'
    },
    {
        name: 'JW Player API Key',
        pattern: /(?:jw[_-]?player[_-]?api[_-]?key|jwplayer[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'JW Player API Key',
        confidence: 'high'
    },
    {
        name: 'Brightcove API Key',
        pattern: /(?:brightcove[_-]?api[_-]?key|brightcove[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Brightcove API Key',
        confidence: 'high'
    },
    {
        name: 'Kaltura API Secret',
        pattern: /(?:kaltura[_-]?api[_-]?secret|kaltura[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Kaltura API Secret',
        confidence: 'high'
    },
    {
        name: 'Daily.co API Key',
        pattern: /(?:daily[_-]?co[_-]?api[_-]?key|daily[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Daily.co API Key',
        confidence: 'high'
    },

    // Additional Blockchain & Crypto Services
    {
        name: 'Coinbase API Key',
        pattern: /(?:coinbase[_-]?api[_-]?key|coinbase[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Coinbase API Key',
        confidence: 'high'
    },
    {
        name: 'Coinbase API Secret',
        pattern: /(?:coinbase[_-]?api[_-]?secret|coinbase[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Coinbase API Secret',
        confidence: 'high'
    },
    {
        name: 'Binance API Key',
        pattern: /(?:binance[_-]?api[_-]?key|binance[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Binance API Key',
        confidence: 'high'
    },
    {
        name: 'Binance API Secret',
        pattern: /(?:binance[_-]?api[_-]?secret|binance[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Binance API Secret',
        confidence: 'high'
    },
    {
        name: 'Kraken API Key',
        pattern: /(?:kraken[_-]?api[_-]?key|kraken[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Kraken API Key',
        confidence: 'high'
    },
    {
        name: 'Kraken API Secret',
        pattern: /(?:kraken[_-]?api[_-]?secret|kraken[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Kraken API Secret',
        confidence: 'high'
    },
    {
        name: 'Bitfinex API Key',
        pattern: /(?:bitfinex[_-]?api[_-]?key|bitfinex[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Bitfinex API Key',
        confidence: 'high'
    },
    {
        name: 'Bitfinex API Secret',
        pattern: /(?:bitfinex[_-]?api[_-]?secret|bitfinex[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Bitfinex API Secret',
        confidence: 'high'
    },
    {
        name: 'Gemini API Secret',
        pattern: /(?:gemini[_-]?api[_-]?secret|gemini[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Gemini API Secret',
        confidence: 'high'
    },
    {
        name: 'Poloniex API Key',
        pattern: /(?:poloniex[_-]?api[_-]?key|poloniex[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Poloniex API Key',
        confidence: 'high'
    },

    // Additional Location & Maps Services
    {
        name: 'Google Maps API Key (expanded)',
        pattern: /(?:google[_-]?maps[_-]?api[_-]?key|gmaps[_-]?api[_-]?key|maps[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Maps API Key',
        confidence: 'high'
    },
    {
        name: 'Mapbox Secret Access Token',
        pattern: /(?:mapbox[_-]?secret[_-]?access[_-]?token|mapbox[_-]?secret)\s*[:=]\s*["']?(sk\.[a-zA-Z0-9\-_]{60,})["']?/gi,
        suggestion: 'Mapbox Secret Access Token',
        confidence: 'high'
    },
    {
        name: 'Mapbox Secret Token',
        pattern: /sk\.[a-zA-Z0-9\-_]{60,}/g,
        suggestion: 'Mapbox Secret Token',
        confidence: 'high'
    },
    {
        name: 'Here API Key (expanded)',
        pattern: /(?:here[_-]?api[_-]?key|here[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Here API Key',
        confidence: 'high'
    },
    {
        name: 'TomTom API Key (expanded)',
        pattern: /(?:tomtom[_-]?api[_-]?key|tomtom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'TomTom API Key',
        confidence: 'high'
    },
    {
        name: 'Foursquare Client Secret (expanded)',
        pattern: /(?:foursquare[_-]?client[_-]?secret|foursquare[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Foursquare Client Secret',
        confidence: 'high'
    },
    {
        name: 'Yelp API Key (expanded)',
        pattern: /(?:yelp[_-]?api[_-]?key|yelp[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
        suggestion: 'Yelp API Key',
        confidence: 'high'
    },
    {
        name: 'OpenCage API Key',
        pattern: /(?:opencage[_-]?api[_-]?key|opencage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'OpenCage API Key',
        confidence: 'high'
    },
    {
        name: 'Geocodio API Key',
        pattern: /(?:geocodio[_-]?api[_-]?key|geocodio[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Geocodio API Key',
        confidence: 'high'
    },
    {
        name: 'SmartyStreets API Key',
        pattern: /(?:smartystreets[_-]?api[_-]?key|smartystreets[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'SmartyStreets API Key',
        confidence: 'high'
    },

    // Additional Form & Survey Services
    {
        name: 'Typeform Personal Token',
        pattern: /(?:typeform[_-]?personal[_-]?token|typeform[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Typeform Personal Token',
        confidence: 'high'
    },
    {
        name: 'Google Forms API Key',
        pattern: /(?:google[_-]?forms[_-]?api[_-]?key|googleforms[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Forms API Key',
        confidence: 'high'
    },
    {
        name: 'JotForm API Key',
        pattern: /(?:jotform[_-]?api[_-]?key|jotform[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'JotForm API Key',
        confidence: 'high'
    },
    {
        name: 'Wufoo API Key',
        pattern: /(?:wufoo[_-]?api[_-]?key|wufoo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Wufoo API Key',
        confidence: 'high'
    },
    {
        name: 'Formstack API Key',
        pattern: /(?:formstack[_-]?api[_-]?key|formstack[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'Formstack API Key',
        confidence: 'high'
    },
    {
        name: 'SurveyMonkey API Key',
        pattern: /(?:surveymonkey[_-]?api[_-]?key|surveymonkey[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'SurveyMonkey API Key',
        confidence: 'high'
    },
    {
        name: 'Qualtrics API Token',
        pattern: /(?:qualtrics[_-]?api[_-]?token|qualtrics[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{40,})["']?/gi,
        suggestion: 'Qualtrics API Token',
        confidence: 'high'
    },
    {
        name: 'LimeSurvey API Key',
        pattern: /(?:limesurvey[_-]?api[_-]?key|limesurvey[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'LimeSurvey API Key',
        confidence: 'high'
    },
    {
        name: 'Google Sheets API Key',
        pattern: /(?:google[_-]?sheets[_-]?api[_-]?key|googlesheets[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Sheets API Key',
        confidence: 'high'
    },
    {
        name: 'Airtable API Key (expanded)',
        pattern: /(?:airtable[_-]?api[_-]?key|airtable[_-]?key)\s*[:=]\s*["']?(pat[a-zA-Z0-9\-_]{17})["']?/gi,
        suggestion: 'Airtable API Key',
        confidence: 'high'
    },

    // Additional File Storage & CDN
    {
        name: 'Dropbox Access Token',
        pattern: /(?:dropbox[_-]?access[_-]?token|dropbox[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{64})["']?/gi,
        suggestion: 'Dropbox Access Token',
        confidence: 'high'
    },
    {
        name: 'Dropbox App Secret',
        pattern: /(?:dropbox[_-]?app[_-]?secret|dropbox[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{15})["']?/gi,
        suggestion: 'Dropbox App Secret',
        confidence: 'high'
    },
    {
        name: 'Box API Key',
        pattern: /(?:box[_-]?api[_-]?key|box[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Box API Key',
        confidence: 'high'
    },
    {
        name: 'Box Client Secret',
        pattern: /(?:box[_-]?client[_-]?secret|box[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
        suggestion: 'Box Client Secret',
        confidence: 'high'
    },
    {
        name: 'OneDrive Client Secret',
        pattern: /(?:onedrive[_-]?client[_-]?secret|onedrive[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
        suggestion: 'OneDrive Client Secret',
        confidence: 'high'
    },
    {
        name: 'Google Drive API Key',
        pattern: /(?:google[_-]?drive[_-]?api[_-]?key|googledrive[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        suggestion: 'Google Drive API Key',
        confidence: 'high'
    },
    {
        name: 'Amazon S3 Secret Access Key',
        pattern: /(?:amazon[_-]?s3[_-]?secret[_-]?access[_-]?key|s3[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{40})["']?/gi,
        suggestion: 'Amazon S3 Secret Access Key',
        confidence: 'high'
    },
    {
        name: 'Wasabi Secret Access Key',
        pattern: /(?:wasabi[_-]?secret[_-]?access[_-]?key|wasabi[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/]{40})["']?/gi,
        suggestion: 'Wasabi Secret Access Key',
        confidence: 'high'
    },
    {
        name: 'Backblaze B2 Application Key ID',
        pattern: /(?:backblaze[_-]?b2[_-]?application[_-]?key[_-]?id|b2[_-]?app[_-]?key[_-]?id)\s*[:=]\s*["']?([a-zA-Z0-9]{25})["']?/gi,
        suggestion: 'Backblaze B2 Application Key ID',
        confidence: 'high'
    },
    {
        name: 'MinIO Access Key',
        pattern: /(?:minio[_-]?access[_-]?key|minio[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{20})["']?/gi,
        suggestion: 'MinIO Access Key',
        confidence: 'high'
    }
];
