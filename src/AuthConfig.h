/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#ifndef D_AUTH_CONFIG_H
#define D_AUTH_CONFIG_H

#include "common.h"

#include <string>
#include <iosfwd>
#include <memory>

namespace aria2 {

typedef enum {
  AUTH_NONE,
  AUTH_BASIC,
  AUTH_DIGEST,
  MAX_SUPPORTED_SCHEME,
} AuthScheme;

struct DigestAuthParams {
  std::string serverNonce;
  // The following properties are generated when responding to the challenge:
  std::string realm;
  std::string clientNonce;
  std::string qop;
  std::string response;
  std::string algorithm;
  std::string uri;
};

class AuthConfig {
private:
  AuthScheme authScheme_;
  std::string user_;
  std::string password_;
  std::string digest_;

public:
  AuthConfig();
  AuthConfig(std::string user, std::string password);
  AuthConfig(std::string user, std::string password, std::string path, std::string method, const std::unique_ptr<DigestAuthParams>& digestAuthParams);
  ~AuthConfig();

  // Don't allow copying
  AuthConfig(const AuthConfig&);
  AuthConfig& operator=(const AuthConfig&);

  std::string getAuthText() const;

  const std::string& getUser() const { return user_; }

  const std::string& getPassword() const { return password_; }

  static std::unique_ptr<AuthConfig> create(std::string user,
                                            std::string password);
  static std::unique_ptr<AuthConfig> create(std::string user,
                                            std::string password,
                                            std::string path, // dir + file path
                                            std::string method,
                                            const std::unique_ptr<DigestAuthParams>& digestAuthParams);
};

std::ostream& operator<<(std::ostream& o,
                         const std::shared_ptr<AuthConfig>& authConfig);

} // namespace aria2

#endif // D_AUTH_CONFIG_H
