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

class PersonalAccessTokensControllerTest < Redmine::ControllerTest
  tests PersonalAccessTokensController

  def setup
    @request.session[:user_id] = 2
  end

  def test_index_lists_only_own_tokens
    get :index
    assert_response :success
    assert_select 'td', :text => 'CI pipeline'
  end

  def test_index_requires_login
    @request.session[:user_id] = nil
    get :index
    assert_response :redirect
  end

  def test_new_renders_form
    get :new
    assert_response :success
    assert_select 'input[name=?]', 'personal_access_token[name]'
  end

  def test_new_clamps_prefilled_expiry_to_max_lifetime
    with_settings :personal_access_token_max_lifetime_days => '30' do
      get :new
      assert_response :success
      expected = 30.days.from_now.to_date.iso8601
      assert_select 'input[name=?][value=?]', 'personal_access_token[expires_on]', expected
    end
  end

  def test_create_shows_plaintext_exactly_once
    assert_difference 'PersonalAccessToken.count', 1 do
      post :create, :params => {
        :personal_access_token => {:name => 'deploy', :expires_on => 30.days.from_now.to_date.to_s}
      }
    end
    assert_response :success
    assert_select 'code.pat-value', :text => /\Armpat_[a-f0-9]{64}\z/
  end

  def test_index_never_shows_plaintext
    get :index
    assert_select 'code.pat-value', 0
    assert_select 'td', :text => 'rmpat_…aaaa'
  end

  def test_create_without_params_does_not_error
    assert_no_difference 'PersonalAccessToken.count' do
      post :create
    end
    assert_response :success
  end

  def test_create_rejects_missing_name
    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {
        :personal_access_token => {:name => '', :expires_on => 30.days.from_now.to_date.to_s}
      }
    end
    assert_response :success
    assert_select_error /Name cannot be blank/
  end

  def test_revoke_marks_own_token_revoked
    post :revoke, :params => {:id => 1}
    assert_redirected_to personal_access_tokens_path
    assert PersonalAccessToken.find(1).revoked?
  end

  def test_revoke_cannot_touch_another_users_token
    @request.session[:user_id] = 3
    post :revoke, :params => {:id => 1}
    assert_response :not_found
    assert_not PersonalAccessToken.find(1).revoked?
  end
end
