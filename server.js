// Pike13 to HighLevel Webhook Bridge Service
// Dockerfile and package.json included at bottom

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
});
app.use(limiter);

// Logging setup
const logger = {
  info: (msg, data) => console.log(JSON.stringify({ level: 'info', message: msg, data, timestamp: new Date().toISOString() })),
  error: (msg, error) => console.error(JSON.stringify({ level: 'error', message: msg, error: error.message, timestamp: new Date().toISOString() })),
  warn: (msg, data) => console.warn(JSON.stringify({ level: 'warn', message: msg, data, timestamp: new Date().toISOString() }))
};

// Environment variables
const config = {
  highlevelWebhooks: {
    personCreated: process.env.HIGHLEVEL_PERSON_CREATED_WEBHOOK,
    personUpdated: process.env.HIGHLEVEL_PERSON_UPDATED_WEBHOOK,
    visitNew: process.env.HIGHLEVEL_VISIT_NEW_WEBHOOK,
    visitUpdated: process.env.HIGHLEVEL_VISIT_UPDATED_WEBHOOK,
    invoiceNew: process.env.HIGHLEVEL_INVOICE_NEW_WEBHOOK,
    transactionCreated: process.env.HIGHLEVEL_TRANSACTION_CREATED_WEBHOOK,
    eventOccurrenceCreated: process.env.HIGHLEVEL_EVENT_OCCURRENCE_CREATED_WEBHOOK
  },
  pike13WebhookSecret: process.env.PIKE13_WEBHOOK_SECRET,
  retryAttempts: parseInt(process.env.RETRY_ATTEMPTS) || 3,
  retryDelay: parseInt(process.env.RETRY_DELAY) || 1000
};

// Validate Pike13 webhook signature (optional but recommended)
function validatePike13Signature(payload, signature) {
  if (!config.pike13WebhookSecret) return true; // Skip validation if no secret set
  
  const expectedSignature = crypto
    .createHmac('sha256', config.pike13WebhookSecret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

// Transform Pike13 person data to HighLevel format
function transformPersonData(pike13Person) {
  return {
    firstName: pike13Person.first_name,
    lastName: pike13Person.last_name,
    email: pike13Person.email,
    phone: pike13Person.phone,
    tags: ['pike13-client'],
    customFields: {
      pike13_id: pike13Person.id.toString(),
      pike13_joined_at: pike13Person.joined_at,
      pike13_is_member: pike13Person.is_member,
      pike13_location: pike13Person.location?.name,
      pike13_timezone: pike13Person.timezone
    },
    source: 'Pike13 Integration'
  };
}

// Transform Pike13 visit data to HighLevel format
function transformVisitData(pike13Visit) {
  const eventOccurrence = pike13Visit.event_occurrence;
  
  return {
    contactId: pike13Visit.person?.id?.toString(),
    title: eventOccurrence?.name || 'Pike13 Class',
    appointmentStatus: pike13Visit.state === 'completed' ? 'confirmed' : 'new',
    startTime: eventOccurrence?.start_at,
    endTime: eventOccurrence?.end_at,
    notes: `Pike13 Visit ID: ${pike13Visit.id}\nService: ${eventOccurrence?.service_name}\nLocation: ${eventOccurrence?.location?.name}`,
    customFields: {
      pike13_visit_id: pike13Visit.id.toString(),
      pike13_event_id: eventOccurrence?.event_id?.toString(),
      pike13_service_type: eventOccurrence?.service_type,
      pike13_visit_state: pike13Visit.state,
      pike13_paid: pike13Visit.paid
    }
  };
}

// Transform Pike13 invoice data to HighLevel format
function transformInvoiceData(pike13Invoice) {
  return {
    contactId: pike13Invoice.person?.id?.toString(),
    amount: pike13Invoice.total_cents / 100,
    currency: pike13Invoice.currency,
    status: pike13Invoice.state,
    invoiceNumber: pike13Invoice.invoice_number,
    invoiceDate: pike13Invoice.invoice_date,
    customFields: {
      pike13_invoice_id: pike13Invoice.id.toString(),
      pike13_outstanding_amount: pike13Invoice.outstanding_amount_cents / 100,
      pike13_discount_total: pike13Invoice.discount_total_cents / 100
    }
  };
}

// Transform Pike13 transaction data to HighLevel format
function transformTransactionData(pike13Transaction) {
  return {
    contactId: pike13Transaction.invoice?.person?.id?.toString(),
    amount: pike13Transaction.amount_cents / 100,
    currency: pike13Transaction.currency_code,
    paymentType: pike13Transaction.payment_type,
    status: pike13Transaction.state,
    transactionId: pike13Transaction.id.toString(),
    customFields: {
      pike13_transaction_id: pike13Transaction.id.toString(),
      pike13_invoice_id: pike13Transaction.invoice_id?.toString(),
      pike13_payment_type: pike13Transaction.payment_type,
      pike13_settled: pike13Transaction.settled,
      pike13_external_transaction_id: pike13Transaction.external_transaction_id
    }
  };
}

// Send data to HighLevel with retry logic
async function sendToHighLevel(webhookUrl, data, attempt = 1) {
  try {
    const response = await axios.post(webhookUrl, data, {
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Pike13-HighLevel-Bridge/1.0'
      }
    });
    
    logger.info('Successfully sent to HighLevel', { 
      status: response.status, 
      attempt,
      dataType: data.type || 'unknown'
    });
    
    return response;
  } catch (error) {
    logger.error(`Failed to send to HighLevel (attempt ${attempt})`, error);
    
    if (attempt < config.retryAttempts) {
      const delay = config.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
      logger.info(`Retrying in ${delay}ms`, { attempt: attempt + 1 });
      
      await new Promise(resolve => setTimeout(resolve, delay));
      return sendToHighLevel(webhookUrl, data, attempt + 1);
    }
    
    throw error;
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Main Pike13 webhook receiver
app.post('/webhook/pike13', async (req, res) => {
  try {
    const signature = req.headers['x-pike13-signature'];
    const payload = JSON.stringify(req.body);
    
    // Validate signature if secret is configured
    if (config.pike13WebhookSecret && !validatePike13Signature(payload, signature)) {
      logger.warn('Invalid Pike13 webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const { topic, data, webhook_id, business_id } = req.body;
    
    logger.info('Received Pike13 webhook', { 
      topic, 
      webhook_id, 
      business_id,
      dataKeys: Object.keys(data || {})
    });
    
    let transformedData;
    let targetWebhook;
    
    // Route based on Pike13 topic
    switch (topic) {
      case 'person.created':
        if (data.people && data.people[0]) {
          transformedData = transformPersonData(data.people[0]);
          transformedData.type = 'person_created';
          targetWebhook = config.highlevelWebhooks.personCreated;
        }
        break;
        
      case 'person.updated':
        if (data.people && data.people[0]) {
          transformedData = transformPersonData(data.people[0]);
          transformedData.type = 'person_updated';
          transformedData.previousData = data.previous;
          targetWebhook = config.highlevelWebhooks.personUpdated;
        }
        break;
        
      case 'visit.new':
        if (data.visits && data.visits[0]) {
          transformedData = transformVisitData(data.visits[0]);
          transformedData.type = 'visit_new';
          targetWebhook = config.highlevelWebhooks.visitNew;
        }
        break;
        
      case 'visit.updated':
        if (data.visits && data.visits[0]) {
          transformedData = transformVisitData(data.visits[0]);
          transformedData.type = 'visit_updated';
          transformedData.previousData = data.previous;
          targetWebhook = config.highlevelWebhooks.visitUpdated;
        }
        break;
        
      case 'invoice.new':
        if (data.invoices && data.invoices[0]) {
          transformedData = transformInvoiceData(data.invoices[0]);
          transformedData.type = 'invoice_new';
          targetWebhook = config.highlevelWebhooks.invoiceNew;
        }
        break;
        
      case 'transaction.created':
        if (data.transactions && data.transactions[0]) {
          transformedData = transformTransactionData(data.transactions[0]);
          transformedData.type = 'transaction_created';
          targetWebhook = config.highlevelWebhooks.transactionCreated;
        }
        break;
        
      case 'event_occurrence.created':
        if (data.event_occurrences && data.event_occurrences[0]) {
          transformedData = {
            type: 'event_occurrence_created',
            eventData: data.event_occurrences[0]
          };
          targetWebhook = config.highlevelWebhooks.eventOccurrenceCreated;
        }
        break;
        
      default:
        logger.warn('Unhandled Pike13 topic', { topic });
        return res.status(200).json({ message: 'Topic not configured for routing' });
    }
    
    if (!targetWebhook) {
      logger.warn('No HighLevel webhook configured for topic', { topic });
      return res.status(200).json({ message: 'No target webhook configured' });
    }
    
    if (!transformedData) {
      logger.warn('No data to transform', { topic, data });
      return res.status(200).json({ message: 'No data to process' });
    }
    
    // Add metadata
    transformedData.metadata = {
      pike13Topic: topic,
      pike13WebhookId: webhook_id,
      pike13BusinessId: business_id,
      processedAt: new Date().toISOString(),
      bridgeVersion: '1.0.0'
    };
    
    // Send to HighLevel
    await sendToHighLevel(targetWebhook, transformedData);
    
    res.status(200).json({ 
      message: 'Webhook processed successfully',
      topic,
      targetConfigured: !!targetWebhook
    });
    
  } catch (error) {
    logger.error('Error processing Pike13 webhook', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Test endpoint for development
app.post('/test/pike13', (req, res) => {
  logger.info('Test webhook received', req.body);
  res.json({ message: 'Test webhook received', data: req.body });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((error, req, res, next) => {
  logger.error('Unhandled error', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Pike13-HighLevel Bridge Service running on port ${PORT}`);
  
  // Log configuration status
  const configuredWebhooks = Object.entries(config.highlevelWebhooks)
    .filter(([key, value]) => value)
    .map(([key]) => key);
    
  logger.info('Configured HighLevel webhooks', { webhooks: configuredWebhooks });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

