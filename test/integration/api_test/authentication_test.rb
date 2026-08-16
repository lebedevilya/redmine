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

class Redmine::ApiTest::AuthenticationTest < Redmine::ApiTest::Base
  def teardown
    User.current = nil
  end

  def test_api_should_deny_without_credentials
    get '/users/current.xml'
    assert_response :unauthorized
    assert response.headers.has_key?('WWW-Authenticate')
  end

  def test_api_should_accept_http_basic_auth_using_username_and_password
    user = User.generate! do |user|
      user.password = 'my_password'
    end
    get '/users/current.xml', :headers => credentials(user.login, 'my_password')
    assert_response :ok
  end

  def test_api_should_deny_http_basic_auth_using_username_and_wrong_password
    user = User.generate! do |user|
      user.password = 'my_password'
    end
    get '/users/current.xml', :headers => credentials(user.login, 'wrong_password')
    assert_response :unauthorized
  end

  def test_api_should_deny_http_basic_auth_if_twofa_is_active
    user = User.generate! do |user|
      user.password = 'my_password'
      user.update(twofa_scheme: 'totp')
    end
    get '/users/current.xml', :headers => credentials(user.login, 'my_password')
    assert_response :unauthorized
  end

  def test_api_should_accept_http_basic_auth_using_api_key
    user = User.generate!
    token = Token.create!(:user => user, :action => 'api')
    get '/users/current.xml', :headers => credentials(token.value, 'X')
    assert_response :ok
  end

  def test_api_should_deny_http_basic_auth_using_wrong_api_key
    user = User.generate!
    token = Token.create!(:user => user, :action => 'feeds') # not the API key
    get '/users/current.xml', :headers => credentials(token.value, 'X')
    assert_response :unauthorized
  end

  def test_api_should_accept_auth_using_api_key_as_parameter
    user = User.generate!
    token = Token.create!(:user => user, :action => 'api')
    get "/users/current.xml?key=#{token.value}"
    assert_response :ok
  end

  def test_api_should_deny_auth_using_wrong_api_key_as_parameter
    user = User.generate!
    token = Token.create!(:user => user, :action => 'feeds') # not the API key
    get "/users/current.xml?key=#{token.value}"
    assert_response :unauthorized
  end

  def test_api_should_accept_auth_using_api_key_as_request_header
    user = User.generate!
    token = Token.create!(:user => user, :action => 'api')
    get "/users/current.xml", :headers => {'X-Redmine-API-Key' => token.value.to_s}
    assert_response :ok
  end

  def test_api_should_deny_auth_using_wrong_api_key_as_request_header
    user = User.generate!
    token = Token.create!(:user => user, :action => 'feeds') # not the API key
    get "/users/current.xml", :headers => {'X-Redmine-API-Key' => token.value.to_s}
    assert_response :unauthorized
  end

  def test_api_should_trigger_basic_http_auth_with_basic_authorization_header
    ApplicationController.any_instance.expects(:authenticate_with_http_basic).once
    get '/users/current.xml', :headers => credentials('jsmith')
    assert_response :unauthorized
  end

  def test_api_should_not_trigger_basic_http_auth_with_non_basic_authorization_header
    ApplicationController.any_instance.expects(:authenticate_with_http_basic).never
    get '/users/current.xml', :headers => {'HTTP_AUTHORIZATION' => 'Digest foo bar'}
    assert_response :unauthorized
  end

  def test_invalid_utf8_credentials_should_not_trigger_an_error
    invalid_utf8 = "\x82"
    assert !invalid_utf8.valid_encoding?
    assert_nothing_raised do
      get '/users/current.xml', :headers => credentials(invalid_utf8, "foo")
    end
  end

  def test_api_request_should_not_use_user_session
    log_user('jsmith', 'jsmith')

    get '/users/current'
    assert_response :success

    get '/users/current.json'
    assert_response :unauthorized
  end

  # TODO: check why this test does not use the API endpoint
  def test_api_should_accept_switch_user_header_for_admin_user
    user = User.find(1)
    su = User.find(4)

    get '/users/current', :headers => {'X-Redmine-API-Key' => user.api_key, 'X-Redmine-Switch-User' => su.login}
    assert_response :success
    assert_select 'h2', :text => "#{su.initials} #{su.name}"
  end

  # TODO: check why this test does not use the API endpoint
  def test_api_should_respond_with_412_when_trying_to_switch_to_a_invalid_user
    get '/users/current', :headers => {'X-Redmine-API-Key' => User.find(1).api_key, 'X-Redmine-Switch-User' => 'foobar'}
    assert_response :precondition_failed
  end

  # TODO: check why this test does not use the API endpoint
  def test_api_should_respond_with_412_when_trying_to_switch_to_a_locked_user
    user = User.find(5)
    assert user.locked?

    get '/users/current', :headers => {'X-Redmine-API-Key' => User.find(1).api_key, 'X-Redmine-Switch-User' => user.login}
    assert_response :precondition_failed
  end

  # TODO: check why this test does not use the API endpoint
  def test_api_should_not_accept_switch_user_header_for_non_admin_user
    user = User.find(2)
    su = User.find(4)

    get '/users/current', :headers => {'X-Redmine-API-Key' => user.api_key, 'X-Redmine-Switch-User' => su.login}
    assert_response :success
    assert_select 'h2', :text => "#{user.initials} #{user.name}"
  end

  PAT_VALUE = "rmpat_#{'a' * 64}"

  def test_api_should_accept_pat_in_header
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => PAT_VALUE}
    assert_response :ok
    assert_select 'user id', :text => '2'
  end

  def test_api_should_reject_pat_in_key_param
    get '/users/current.xml', :params => {:key => PAT_VALUE}
    assert_response :unauthorized
  end

  def test_api_should_explain_how_to_send_a_pat_when_refused_in_key_param
    get '/users/current.xml', :params => {:key => PAT_VALUE}
    assert_response :unauthorized
    assert_include 'X-Redmine-API-Key', response.body
  end

  def test_api_should_never_echo_the_token_when_refusing_it
    get '/users/current.xml', :params => {:key => PAT_VALUE}
    assert_not_include PAT_VALUE, response.body
  end

  def test_api_should_never_echo_the_token_when_refusing_it_in_html_format
    get '/users/current', :params => {:key => PAT_VALUE}
    assert_response :unauthorized
    assert_not_include PAT_VALUE, response.body
  end

  def test_api_should_still_accept_legacy_api_key_in_key_param
    user = User.find(2)
    get '/users/current.xml', :params => {:key => user.api_key}
    assert_response :ok
    assert_select 'user id', :text => '2'
  end

  def test_api_should_accept_pat_in_http_basic_username_slot
    get '/users/current.xml', :headers => credentials(PAT_VALUE, 'x')
    assert_response :ok
  end

  def test_api_should_still_accept_legacy_api_key
    user = User.find(2)
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => user.api_key}
    assert_response :ok
    assert_select 'user id', :text => '2'
  end

  def test_api_should_reject_expired_pat
    PersonalAccessToken.find(1).update_column(:expires_on, 1.day.ago.to_date)
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => PAT_VALUE}
    assert_response :unauthorized
  end

  def test_api_should_reject_revoked_pat
    PersonalAccessToken.find(1).revoke!
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => PAT_VALUE}
    assert_response :unauthorized
  end

  def test_api_should_update_last_used_at_on_successful_pat_auth
    assert_nil PersonalAccessToken.find(1).last_used_at
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => PAT_VALUE}
    assert_response :ok
    assert_not_nil PersonalAccessToken.find(1).last_used_at
  end
end
