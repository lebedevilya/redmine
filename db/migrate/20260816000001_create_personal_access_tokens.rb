# frozen_string_literal: true

class CreatePersonalAccessTokens < ActiveRecord::Migration[7.2]
  def change
    create_table :personal_access_tokens do |t|
      t.references :user, :null => false
      t.string   :name,       :null => false
      t.string   :token_hash, :null => false
      t.string   :last_four,  :null => false
      t.text     :scopes
      t.date     :expires_on, :null => false
      t.datetime :last_used_at
      t.datetime :revoked_at
      t.timestamps :null => false
    end
    add_index :personal_access_tokens, :token_hash, :unique => true
  end
end
