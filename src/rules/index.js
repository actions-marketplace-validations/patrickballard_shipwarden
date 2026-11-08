import secrets from './secrets.js';
import supabase from './supabase.js';
import firebase from './firebase.js';
import web from './web.js';

export const RULES = [...secrets, ...supabase, ...firebase, ...web];
export const RULE_IDS = new Set(RULES.map((r) => r.id));
