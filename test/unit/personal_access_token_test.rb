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

require_relative '../test_helper'

class PersonalAccessTokenTest < ActiveSupport::TestCase
  FIXTURE_VALUE = "rmpat_#{'a' * 64}"

  def setup
    User.current = nil
    @user = User.find(2)
  end

  def test_generate_returns_record_and_plaintext
    token, plaintext = PersonalAccessToken.generate!(@user, :name => 'ci', :expires_on => 30.days.from_now.to_date)
    assert token.persisted?
    assert_match(/\Armpat_[a-f0-9]{64}\z/, plaintext)
    assert_equal Digest::SHA256.hexdigest(plaintext), token.token_hash
    assert_equal plaintext[-4..], token.last_four
  end

  def test_plaintext_is_never_persisted
    _token, plaintext = PersonalAccessToken.generate!(@user, :name => 'ci', :expires_on => 30.days.from_now.to_date)
    assert_nil PersonalAccessToken.column_names.detect {|c| c == 'value'}
    assert_not_equal plaintext, PersonalAccessToken.last.token_hash
  end

  def test_authenticate_returns_token_for_valid_value
    assert_equal 1, PersonalAccessToken.authenticate(FIXTURE_VALUE).id
  end

  def test_authenticate_returns_nil_for_unknown_value
    assert_nil PersonalAccessToken.authenticate("rmpat_#{'b' * 64}")
  end

  def test_authenticate_rejects_malformed_value_without_db_hit
    assert_nil PersonalAccessToken.authenticate('not-a-token')
    assert_nil PersonalAccessToken.authenticate('')
    assert_nil PersonalAccessToken.authenticate(nil)
  end

  def test_authenticate_rejects_expired_token
    PersonalAccessToken.find(1).update_column(:expires_on, 1.day.ago.to_date)
    assert_nil PersonalAccessToken.authenticate(FIXTURE_VALUE)
  end

  def test_authenticate_rejects_revoked_token
    PersonalAccessToken.find(1).revoke!
    assert_nil PersonalAccessToken.authenticate(FIXTURE_VALUE)
  end

  def test_find_active_user_rejects_locked_user
    @user.update_column(:status, User::STATUS_LOCKED)
    assert_nil PersonalAccessToken.find_active_user(FIXTURE_VALUE)
  end

  def test_find_active_user_returns_owner
    assert_equal @user, PersonalAccessToken.find_active_user(FIXTURE_VALUE)
  end

  def test_expires_on_is_mandatory
    token = PersonalAccessToken.new(:user => @user, :name => 'x')
    assert_not token.valid?
    assert_includes token.errors.attribute_names, :expires_on
  end

  def test_name_is_mandatory
    token = PersonalAccessToken.new(:user => @user, :expires_on => 1.day.from_now.to_date)
    assert_not token.valid?
    assert_includes token.errors.attribute_names, :name
  end

  def test_expires_on_must_be_in_the_future
    token = PersonalAccessToken.new(:user => @user, :name => 'x', :expires_on => 1.day.ago.to_date)
    assert_not token.valid?
  end

  def test_touch_last_used_writes_when_never_used
    token = PersonalAccessToken.find(1)
    assert_nil token.last_used_at
    token.touch_last_used!
    assert_not_nil token.reload.last_used_at
  end

  def test_touch_last_used_is_throttled_within_an_hour
    token = PersonalAccessToken.find(1)
    recent = 5.minutes.ago
    token.update_column(:last_used_at, recent)
    token.touch_last_used!
    assert_in_delta recent.to_i, token.reload.last_used_at.to_i, 1
  end

  def test_touch_last_used_writes_when_stale
    token = PersonalAccessToken.find(1)
    token.update_column(:last_used_at, 2.hours.ago)
    token.touch_last_used!
    assert token.reload.last_used_at > 1.hour.ago
  end

  def test_display_value_masks_the_secret
    assert_equal 'rmpat_…aaaa', PersonalAccessToken.find(1).display_value
  end
end
