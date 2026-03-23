import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

@Injectable()
export class SupabaseService {
  private client: SupabaseClient;
  private anonClient: SupabaseClient;

  constructor(private config: ConfigService) {
    const url = this.config.getOrThrow<string>('SUPABASE_URL');

    this.client = createClient(
      url,
      this.config.getOrThrow<string>('SUPABASE_SERVICE_ROLE_KEY'),
      { auth: { autoRefreshToken: false, persistSession: false } },
    );

    this.anonClient = createClient(
      url,
      this.config.getOrThrow<string>('SUPABASE_ANON_KEY'),
      { auth: { autoRefreshToken: false, persistSession: false } },
    );
  }

  /** Service-role client: DB queries + auth.admin.* operations */
  get db(): SupabaseClient {
    return this.client;
  }

  /** Anon-key client: signInWithPassword, signInWithIdToken */
  get authClient(): SupabaseClient {
    return this.anonClient;
  }
}
