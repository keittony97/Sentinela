export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  graphql_public: {
    Tables: {
      [_ in never]: never
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      graphql: {
        Args: {
          extensions?: Json
          operationName?: string
          query?: string
          variables?: Json
        }
        Returns: Json
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
  public: {
    Tables: {
      audit_log: {
        Row: {
          action: string
          created_at: string
          entity_id: string | null
          entity_type: string
          id: string
          metadata: Json
          organization_id: string
          user_id: string | null
        }
        Insert: {
          action: string
          created_at?: string
          entity_id?: string | null
          entity_type: string
          id?: string
          metadata?: Json
          organization_id: string
          user_id?: string | null
        }
        Update: {
          action?: string
          created_at?: string
          entity_id?: string | null
          entity_type?: string
          id?: string
          metadata?: Json
          organization_id?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "audit_log_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "audit_log_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      findings: {
        Row: {
          created_at: string
          cwe: string | null
          description: string | null
          evidence: Json
          id: string
          impact: string | null
          organization_id: string
          owasp_category: string | null
          recommendation: string | null
          reference_links: string[]
          remediation_status: Database["public"]["Enums"]["remediation_status"]
          scan_id: string
          severity: Database["public"]["Enums"]["severity_level"]
          title: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          cwe?: string | null
          description?: string | null
          evidence?: Json
          id?: string
          impact?: string | null
          organization_id: string
          owasp_category?: string | null
          recommendation?: string | null
          reference_links?: string[]
          remediation_status?: Database["public"]["Enums"]["remediation_status"]
          scan_id: string
          severity: Database["public"]["Enums"]["severity_level"]
          title: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          cwe?: string | null
          description?: string | null
          evidence?: Json
          id?: string
          impact?: string | null
          organization_id?: string
          owasp_category?: string | null
          recommendation?: string | null
          reference_links?: string[]
          remediation_status?: Database["public"]["Enums"]["remediation_status"]
          scan_id?: string
          severity?: Database["public"]["Enums"]["severity_level"]
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "findings_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      organizations: {
        Row: {
          created_at: string
          id: string
          name: string
        }
        Insert: {
          created_at?: string
          id?: string
          name: string
        }
        Update: {
          created_at?: string
          id?: string
          name?: string
        }
        Relationships: []
      }
      projects: {
        Row: {
          auth_mode: Database["public"]["Enums"]["auth_mode"]
          authorization_confirmed: boolean
          authorization_justification: string | null
          authorization_reference: string | null
          created_at: string
          created_by: string
          id: string
          legal_mode: Database["public"]["Enums"]["legal_mode"]
          name: string
          organization_id: string
          status: Database["public"]["Enums"]["project_status"]
          target_id: string
          updated_at: string
        }
        Insert: {
          auth_mode: Database["public"]["Enums"]["auth_mode"]
          authorization_confirmed?: boolean
          authorization_justification?: string | null
          authorization_reference?: string | null
          created_at?: string
          created_by: string
          id?: string
          legal_mode: Database["public"]["Enums"]["legal_mode"]
          name: string
          organization_id: string
          status?: Database["public"]["Enums"]["project_status"]
          target_id: string
          updated_at?: string
        }
        Update: {
          auth_mode?: Database["public"]["Enums"]["auth_mode"]
          authorization_confirmed?: boolean
          authorization_justification?: string | null
          authorization_reference?: string | null
          created_at?: string
          created_by?: string
          id?: string
          legal_mode?: Database["public"]["Enums"]["legal_mode"]
          name?: string
          organization_id?: string
          status?: Database["public"]["Enums"]["project_status"]
          target_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "projects_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "projects_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "projects_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "targets"
            referencedColumns: ["id"]
          },
        ]
      }
      scan_logs: {
        Row: {
          created_at: string
          id: string
          level: string
          message: string
          organization_id: string
          scan_id: string
          tool: string
        }
        Insert: {
          created_at?: string
          id?: string
          level?: string
          message: string
          organization_id: string
          scan_id: string
          tool: string
        }
        Update: {
          created_at?: string
          id?: string
          level?: string
          message?: string
          organization_id?: string
          scan_id?: string
          tool?: string
        }
        Relationships: [
          {
            foreignKeyName: "scan_logs_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "scan_logs_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      scans: {
        Row: {
          created_at: string
          finished_at: string | null
          id: string
          is_active_tool: boolean
          organization_id: string
          project_id: string
          started_at: string | null
          status: Database["public"]["Enums"]["scan_status"]
          tools_used: string[]
          triggered_by: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          finished_at?: string | null
          id?: string
          is_active_tool?: boolean
          organization_id: string
          project_id: string
          started_at?: string | null
          status?: Database["public"]["Enums"]["scan_status"]
          tools_used?: string[]
          triggered_by: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          finished_at?: string | null
          id?: string
          is_active_tool?: boolean
          organization_id?: string
          project_id?: string
          started_at?: string | null
          status?: Database["public"]["Enums"]["scan_status"]
          tools_used?: string[]
          triggered_by?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "scans_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "scans_project_id_fkey"
            columns: ["project_id"]
            isOneToOne: false
            referencedRelation: "projects"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "scans_triggered_by_fkey"
            columns: ["triggered_by"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      targets: {
        Row: {
          asset_owner: string | null
          created_at: string
          created_by: string
          id: string
          name: string
          organization_id: string
          scope: Database["public"]["Enums"]["target_scope"]
          url: string
        }
        Insert: {
          asset_owner?: string | null
          created_at?: string
          created_by: string
          id?: string
          name: string
          organization_id: string
          scope: Database["public"]["Enums"]["target_scope"]
          url: string
        }
        Update: {
          asset_owner?: string | null
          created_at?: string
          created_by?: string
          id?: string
          name?: string
          organization_id?: string
          scope?: Database["public"]["Enums"]["target_scope"]
          url?: string
        }
        Relationships: [
          {
            foreignKeyName: "targets_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "targets_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      users: {
        Row: {
          created_at: string
          email: string
          full_name: string | null
          id: string
          organization_id: string
          role: Database["public"]["Enums"]["user_role"]
          username: string | null
        }
        Insert: {
          created_at?: string
          email: string
          full_name?: string | null
          id: string
          organization_id: string
          role?: Database["public"]["Enums"]["user_role"]
          username?: string | null
        }
        Update: {
          created_at?: string
          email?: string
          full_name?: string | null
          id?: string
          organization_id?: string
          role?: Database["public"]["Enums"]["user_role"]
          username?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "users_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      can_write: { Args: never; Returns: boolean }
      current_org_id: { Args: never; Returns: string }
      current_role: {
        Args: never
        Returns: Database["public"]["Enums"]["user_role"]
      }
      email_for_username: { Args: { p_username: string }; Returns: string }
      is_admin: { Args: never; Returns: boolean }
      mfa_satisfied: { Args: never; Returns: boolean }
    }
    Enums: {
      auth_mode: "sem_login" | "com_login"
      legal_mode: "verificacao_externa" | "ambiente_teste"
      project_status: "rascunho" | "ativo" | "concluido" | "arquivado"
      remediation_status:
        | "aberto"
        | "em_correcao"
        | "corrigido"
        | "risco_aceito"
      scan_status:
        | "na_fila"
        | "em_execucao"
        | "concluido"
        | "falhou"
        | "cancelado"
      severity_level: "critico" | "alto" | "medio" | "baixo" | "informativo"
      target_scope: "intranet" | "internet"
      user_role: "admin" | "pentester" | "visualizador"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  graphql_public: {
    Enums: {},
  },
  public: {
    Enums: {
      auth_mode: ["sem_login", "com_login"],
      legal_mode: ["verificacao_externa", "ambiente_teste"],
      project_status: ["rascunho", "ativo", "concluido", "arquivado"],
      remediation_status: [
        "aberto",
        "em_correcao",
        "corrigido",
        "risco_aceito",
      ],
      scan_status: [
        "na_fila",
        "em_execucao",
        "concluido",
        "falhou",
        "cancelado",
      ],
      severity_level: ["critico", "alto", "medio", "baixo", "informativo"],
      target_scope: ["intranet", "internet"],
      user_role: ["admin", "pentester", "visualizador"],
    },
  },
} as const
