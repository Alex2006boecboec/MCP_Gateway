-- Migration 005: Add plan column to orgs table (subscription tiers).
-- Allows tracking Free/Pro/Business/Enterprise plan per organization.

ALTER TABLE orgs ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
