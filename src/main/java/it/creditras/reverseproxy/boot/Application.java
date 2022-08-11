package it.creditras.reverseproxy.boot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

/**
 * @author Lucio Regina
 * @version 1.0.0
 * @since 1.0.0
 *
 */
@SpringBootApplication
@Import({ ProxyAutoConfiguration.class })
@EnableDiscoveryClient
public class Application /*extends SpringBootServletInitializer*/{

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
