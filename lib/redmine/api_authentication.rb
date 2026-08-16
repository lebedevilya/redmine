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

module Redmine
  # Resolves an API credential (personal access token or legacy API key) to a
  # user. Lives outside User so that User.find_by_api_key stays a pure finder
  # and the legacy path stays byte-for-byte unmodified.
  module ApiAuthentication
    module_function

    # Returns the authenticated user with the PAT stashed on it, or nil.
    def authenticate(presented)
      presented = presented.to_s
      return nil if presented.blank?

      if (token = PersonalAccessToken.authenticate(presented))
        user = token.user
        return nil unless user&.active?

        token.touch_last_used!
        user.current_api_token = token
        return user
      end

      # Legacy single API key. Untouched path.
      User.find_by_api_key(presented)
    end
  end
end
