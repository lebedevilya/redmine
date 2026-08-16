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

class PersonalAccessTokensController < ApplicationController
  self.main_menu = false

  before_action :require_login
  before_action :find_own_token, :only => [:revoke]

  # Token management is account-security-sensitive, exactly like
  # MyController#reset_api_key (my_controller.rb:29).
  require_sudo_mode :new, :create, :revoke

  def index
    @tokens = User.current.personal_access_tokens.order(:created_at => :desc)
  end

  def new
    @token = PersonalAccessToken.new(:expires_on => default_expires_on)
  end

  def create
    params[:personal_access_token] ||= {}
    name       = params[:personal_access_token][:name]
    expires_on = params[:personal_access_token][:expires_on]
    @token, @plaintext = PersonalAccessToken.generate!(
      User.current, :name => name, :expires_on => expires_on
    )
    render :create
  rescue ActiveRecord::RecordInvalid => e
    @token = e.record
    render :new
  end

  def revoke
    @token.revoke!
    flash[:notice] = l(:notice_successful_update)
    redirect_to personal_access_tokens_path
  end

  private

  def find_own_token
    @token = User.current.personal_access_tokens.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    render_404
  end

  # 90 days, clamped to the configured maximum lifetime when one is set
  # (0 means unlimited). Prevents the form from opening pre-populated with
  # a date that immediately fails validation.
  def default_expires_on
    default = 90.days.from_now.to_date
    max_days = Setting.personal_access_token_max_lifetime_days.to_i
    return default if max_days <= 0

    [default, User.current.today + max_days].min
  end
end
