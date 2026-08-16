# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# A named, expiring, hashed API credential owned by a user.
#
# Deliberately NOT built on Token: that model enforces one-token-per-action
# (max_instances), overwrites #value on create, derives expiry per-action
# rather than per-row, and rejects underscores in its lookup guard. See
# docs/superpowers/specs/2026-08-16-redmine-pat-design.md section 1.
class PersonalAccessToken < ApplicationRecord
  include Redmine::SafeAttributes

  PREFIX = 'rmpat_'
  # The presented credential: prefix + 64 hex chars (256 bits).
  VALUE_FORMAT = /\A#{PREFIX}[a-f0-9]{64}\z/
  # Only write last_used_at if the stored value is at least this stale.
  # Bounds write amplification to one UPDATE per token per hour.
  LAST_USED_PRECISION = 1.hour

  # True if the presented string has the shape of a personal access token.
  # Deliberately does NOT hit the database: this is reachable by
  # unauthenticated callers and is only used to produce a helpful error.
  def self.value_format?(presented)
    VALUE_FORMAT.match?(presented.to_s)
  end

  belongs_to :user

  validates_presence_of :name, :expires_on, :token_hash, :last_four
  validates_uniqueness_of :token_hash, :case_sensitive => true
  validate :validate_expires_on

  after_create_commit :deliver_security_notification_create

  safe_attributes 'name', 'expires_on'

  # Creates a token and returns [record, plaintext]. The plaintext is the only
  # time the caller can ever see the secret; only its digest is stored.
  def self.generate!(user, name:, expires_on:, scopes: nil)
    plaintext = "#{PREFIX}#{Redmine::Utils.random_hex(32)}"
    token = create!(
      :user       => user,
      :name       => name,
      :expires_on => expires_on,
      :scopes     => scopes,
      :token_hash => Digest::SHA256.hexdigest(plaintext),
      :last_four  => plaintext[-4..]
    )
    [token, plaintext]
  end

  # Returns the token for a presented credential, or nil.
  def self.authenticate(presented)
    presented = presented.to_s
    return nil unless VALUE_FORMAT.match?(presented)

    digest = Digest::SHA256.hexdigest(presented)
    token = find_by(:token_hash => digest)
    return nil unless token
    # Defence in depth only: the row was looked up BY this digest, so equality
    # already holds. Kept to mirror Token.find_token and to stay correct if the
    # lookup is ever loosened.
    return nil unless ActiveSupport::SecurityUtils.secure_compare(token.token_hash, digest)
    return nil if token.revoked? || token.expired?

    token
  end

  # Named after Token.find_active_user for familiarity.
  def self.find_active_user(presented)
    token = authenticate(presented)
    token.user if token && token.user&.active?
  end

  def expired?
    expires_on.present? && expires_on < User.current.today
  end

  def revoked?
    revoked_at.present?
  end

  def revoke!
    update_column(:revoked_at, Time.current)
    deliver_security_notification_revoke
    true
  end

  # update_column skips validations, callbacks and updated_at, keeping this to
  # a single narrow UPDATE on the hot authentication path.
  def touch_last_used!
    return if last_used_at.present? && last_used_at > LAST_USED_PRECISION.ago

    update_column(:last_used_at, Time.current)
  end

  def display_value
    "#{PREFIX}…#{last_four}"
  end

  private

  def validate_expires_on
    return if expires_on.blank?

    if expires_on <= User.current.today
      errors.add(:expires_on, :invalid)
      return
    end

    max_days = Setting.pat_max_lifetime_days.to_i
    return if max_days <= 0   # 0 means unlimited

    if expires_on > User.current.today + max_days
      errors.add(:expires_on, :invalid)
    end
  end

  def deliver_security_notification_create
    deliver_security_notification(
      :message => :mail_body_security_notification_pat_add,
      :field   => :label_personal_access_token,
      :value   => name
    )
  end

  def deliver_security_notification_revoke
    deliver_security_notification(
      :message => :mail_body_security_notification_pat_revoke,
      :field   => :label_personal_access_token,
      :value   => name
    )
  end

  # NOTE: value is the token NAME, never the secret.
  def deliver_security_notification(options={})
    Mailer.deliver_security_notification(
      user,
      User.current,
      options.merge(
        :title => :label_my_account,
        :url   => {:controller => 'personal_access_tokens', :action => 'index'}
      )
    )
  end
end
