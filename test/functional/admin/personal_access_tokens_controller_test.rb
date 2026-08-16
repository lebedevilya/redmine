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

require_relative '../../test_helper'

class Admin::PersonalAccessTokensControllerTest < Redmine::ControllerTest
  tests Admin::PersonalAccessTokensController

  def setup
    @request.session[:user_id] = 1   # admin
  end

  def test_index_lists_all_users_tokens
    get :index
    assert_response :success
    assert_select 'td', :text => 'CI pipeline'
  end

  def test_index_requires_admin
    @request.session[:user_id] = 2
    get :index
    assert_response :forbidden
  end

  def test_index_never_shows_token_values
    get :index
    assert_select 'code.pat-value', 0
    assert_select 'td', :text => 'rmpat_…aaaa'
    assert_not_includes @response.body, "rmpat_#{'a' * 64}"
  end

  def test_admin_can_revoke_any_users_token
    post :revoke, :params => {:id => 1}
    assert_redirected_to admin_personal_access_tokens_path
    assert PersonalAccessToken.find(1).revoked?
  end
end
