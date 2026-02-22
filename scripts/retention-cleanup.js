#!/usr/bin/env mongosh
'use strict';

function readEnv(name) {
  if (typeof process === 'undefined' || !process.env) return '';
  return String(process.env[name] || '').trim();
}

function parseDbFromURI(uri) {
  try {
    const parsed = new URL(uri);
    const path = String(parsed.pathname || '').replace(/^\/+/, '').trim();
    return path || '';
  } catch (_error) {
    return '';
  }
}

function toInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return parsed;
}

function parseCSV(value, fallbackItems) {
  const raw = String(value || '').trim();
  if (!raw) return [...fallbackItems];
  return raw
    .split(',')
    .map((item) => String(item || '').trim().toLowerCase())
    .filter(Boolean);
}

function parseArgs(rawArgs) {
  const out = {};
  for (const part of rawArgs) {
    if (!part) continue;
    const normalized = String(part).trim();
    if (!normalized) continue;

    if (normalized.startsWith('--')) {
      const eq = normalized.indexOf('=');
      if (eq === -1) {
        out[normalized.slice(2)] = 'true';
      } else {
        out[normalized.slice(2, eq)] = normalized.slice(eq + 1);
      }
      continue;
    }

    const eq = normalized.indexOf('=');
    if (eq !== -1) {
      out[normalized.slice(0, eq)] = normalized.slice(eq + 1);
      continue;
    }
  }
  return out;
}

function printUsage() {
  print([
    '',
    'Usage:',
    '  RETENTION_MODE=dry-run mongosh --quiet scripts/retention-cleanup.js',
    '  RETENTION_MODE=run RETENTION_SOFT_DELETE_DAYS=90 RETENTION_HARD_DELETE_DAYS=365 mongosh --quiet scripts/retention-cleanup.js',
    '',
    'Env vars:',
    '  RETENTION_MODE=dry-run|run              Default: dry-run',
    '  RETENTION_SOFT_DELETE_DAYS=<n>          Default: 120',
    '  RETENTION_HARD_DELETE_DAYS=<n>          Default: 365',
    '  RETENTION_BILLING_STATUSES=a,b,c        Default: canceled,failed,expired',
    '  RETENTION_LEGACY_STATUSES=a,b,c         Default: canceled',
    '  RETENTION_BATCH=<label>                 Optional label for audit fields',
    '',
    'Mongo vars:',
    '  MONGODB_URI_BILLING or MONGODB_URI',
    '  MONGODB_URI_CUSTOMERS or MONGODB_URI',
    '  MONGODB_DB_BILLING (optional if URI has DB path)',
    '  MONGODB_DB_CUSTOMERS (optional if URI has DB path)',
    '',
  ].join('\n'));
}

function olderThanFilter(dateFieldCandidates, thresholdDate) {
  const orParts = [];
  for (const field of dateFieldCandidates) {
    orParts.push({ [field]: { $lt: thresholdDate } });
  }
  return { $or: orParts };
}

const rawArgs = (typeof process !== 'undefined' && Array.isArray(process.argv))
  ? process.argv.slice(2)
  : [];
const args = parseArgs(rawArgs);

if (readEnv('RETENTION_HELP') === 'true' || args.help === 'true' || args.h === 'true') {
  printUsage();
  quit(0);
}

const mode = String(readEnv('RETENTION_MODE') || args.mode || 'dry-run').toLowerCase();
if (mode !== 'dry-run' && mode !== 'run') {
  print(`ERROR: unsupported RETENTION_MODE "${mode}"`);
  printUsage();
  quit(1);
}

const softDeleteDays = Math.max(1, toInt(readEnv('RETENTION_SOFT_DELETE_DAYS') || args.softDeleteDays, 120));
const hardDeleteDays = Math.max(softDeleteDays + 1, toInt(readEnv('RETENTION_HARD_DELETE_DAYS') || args.hardDeleteDays, 365));
const batch = String(readEnv('RETENTION_BATCH') || args.batch || '').trim();
const billingStatuses = parseCSV(
  readEnv('RETENTION_BILLING_STATUSES') || args.billingStatuses,
  ['canceled', 'failed', 'expired']
);
const legacyStatuses = parseCSV(
  readEnv('RETENTION_LEGACY_STATUSES') || args.legacyStatuses,
  ['canceled']
);

const baseURI = readEnv('MONGODB_URI');
const billingURI = readEnv('MONGODB_URI_BILLING') || baseURI;
const customersURI = readEnv('MONGODB_URI_CUSTOMERS') || baseURI;
const billingDB = readEnv('MONGODB_DB_BILLING') || parseDbFromURI(billingURI) || 'snweb-billing';
const customersDB = readEnv('MONGODB_DB_CUSTOMERS') || parseDbFromURI(customersURI) || 'snweb-customers';

if (!billingURI || !customersURI) {
  print('ERROR: Missing Mongo URI. Configure MONGODB_URI_BILLING/MONGODB_URI_CUSTOMERS (or MONGODB_URI).');
  printUsage();
  quit(1);
}

const billingConn = new Mongo(billingURI);
const customersConn = new Mongo(customersURI);
const billingRecords = billingConn.getDB(billingDB).getCollection('billingrecords');
const customerSubscriptions = customersConn.getDB(customersDB).getCollection('customersubscriptions');

const now = new Date();
const softDeleteBefore = new Date(now.getTime() - softDeleteDays * 24 * 60 * 60 * 1000);
const hardDeleteBefore = new Date(now.getTime() - hardDeleteDays * 24 * 60 * 60 * 1000);

const billingSoftFilter = {
  deletedAt: { $exists: false },
  status: { $in: billingStatuses },
  ...olderThanFilter(['updatedAt', 'createdAt'], softDeleteBefore),
};
const subscriptionsSoftFilter = {
  deletedAt: { $exists: false },
  status: { $in: legacyStatuses },
  ...olderThanFilter(['updatedAt', 'lastInvoiceAt'], softDeleteBefore),
};

const billingHardFilter = {
  deletedAt: { $lt: hardDeleteBefore },
};
const subscriptionsHardFilter = {
  deletedAt: { $lt: hardDeleteBefore },
};

const preview = {
  billingSoftCandidates: billingRecords.countDocuments(billingSoftFilter),
  subscriptionsSoftCandidates: customerSubscriptions.countDocuments(subscriptionsSoftFilter),
  billingHardCandidates: billingRecords.countDocuments(billingHardFilter),
  subscriptionsHardCandidates: customerSubscriptions.countDocuments(subscriptionsHardFilter),
};

if (mode === 'dry-run') {
  print(JSON.stringify({
    ok: true,
    mode,
    softDeleteDays,
    hardDeleteDays,
    billingStatuses,
    legacyStatuses,
    softDeleteBefore,
    hardDeleteBefore,
    preview,
  }, null, 2));
  quit(0);
}

const markPayload = {
  deletedAt: now,
  retentionSource: 'scripts/retention-cleanup.js',
};
if (batch) {
  markPayload.retentionBatch = batch;
}

const billingSoftResult = billingRecords.updateMany(
  billingSoftFilter,
  { $set: markPayload }
);
const subscriptionsSoftResult = customerSubscriptions.updateMany(
  subscriptionsSoftFilter,
  { $set: markPayload }
);
const billingHardResult = billingRecords.deleteMany(billingHardFilter);
const subscriptionsHardResult = customerSubscriptions.deleteMany(subscriptionsHardFilter);

print(JSON.stringify({
  ok: true,
  mode,
  softDeleteDays,
  hardDeleteDays,
  billingStatuses,
  legacyStatuses,
  softDeleteBefore,
  hardDeleteBefore,
  preview,
  executed: {
    billingSoftModified: billingSoftResult.modifiedCount || 0,
    subscriptionsSoftModified: subscriptionsSoftResult.modifiedCount || 0,
    billingHardDeleted: billingHardResult.deletedCount || 0,
    subscriptionsHardDeleted: subscriptionsHardResult.deletedCount || 0,
  },
}, null, 2));
