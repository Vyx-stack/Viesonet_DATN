package com.viesonet.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.viesonet.dao.AccountsDao;
import com.viesonet.dao.UsersDao;
import com.viesonet.entity.AccountStatus;
import com.viesonet.entity.Accounts;
import com.viesonet.entity.Roles;
@Service
public class AccountsService implements UserDetailsService{
	@Autowired
	AccountsDao accountsDao;
	
	@Autowired
	UsersDao usersDao;


	public Accounts getAccountByUsers(String userId) {
        return accountsDao.findByUserId(userId);
    }
	
	public Accounts findByPhoneNumber(String phoneNumber) {
		return accountsDao.findByPhoneNumber(phoneNumber);
	}
	
	public boolean existById(String phoneNumber) {
		return accountsDao.existsById(phoneNumber);
	}
	
	public boolean existByEmail(String email) {
		return accountsDao.existsByEmail(email);
	}
	
	public Accounts save(Accounts accounts) {
		return accountsDao.save(accounts);
	}

	public Accounts setRole(String sdt, int role) {
		Roles roles = new Roles();
		roles.setRoleId(role);
		Accounts accounts = accountsDao.findByPhoneNumber(sdt);
		accounts.setRole(roles);
		return accountsDao.saveAndFlush(accounts);
	}
	
	public void updateAccInfo(String userId,String email, int statusId) {
		Accounts currentAcc = accountsDao.findByUserId(userId);
		AccountStatus status = new AccountStatus();
		currentAcc.setEmail(email);
		status.setStatusId(statusId);
        currentAcc.setAccountStatus(status);
		accountsDao.saveAndFlush(currentAcc);
    }
	
	 public Accounts getAccountById(String userId) {
	        return accountsDao.findById(userId).orElse(null);
	}
	
	 public Accounts findByUserId(String userId) {
		 return accountsDao.findByUserId(userId);
	 }
	 
	 public Accounts findByEmail(String email) {
		return accountsDao.findByEmail(email);
	}

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Truy vấn tài khoản từ cơ sở dữ liệu với tên đăng nhập
        Accounts account = accountsDao.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " not found!"));

        // Trích xuất mật khẩu từ tài khoản
        String password = account.getPassword();
        
        // Trích xuất vai trò từ tài khoản (Roleid trong bảng Accounts)
        String role = account.getRole().getRoleName();

        // Tạo và trả về đối tượng UserDetails được mã hóa mật khẩu và gán vai trò
        return User.withUsername(username)
                .password(password) // Không cần mã hóa mật khẩu vì UserDetailsService mặc định đã làm điều này
                .roles(role) // Gán vai trò
                .build();
    }

	public String getRoleByUsername(String username) {
		// Truy vấn người dùng từ cơ sở dữ liệu theo tên đăng nhập
		Accounts account = accountsDao.findById(username).orElse(null);
	
		if (account != null && account.getRole() != null) {
			return account.getRole().getRoleName();
		}
	
		return null; // Hoặc giá trị mặc định tùy theo yêu cầu của bạn
	}
	


}
