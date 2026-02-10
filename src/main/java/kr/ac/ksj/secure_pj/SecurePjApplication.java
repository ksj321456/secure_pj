package kr.ac.ksj.secure_pj;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(
)
@EnableScheduling
public class SecurePjApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurePjApplication.class, args);
	}

}
