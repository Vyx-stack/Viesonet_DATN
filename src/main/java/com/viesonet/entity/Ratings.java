package com.viesonet.entity;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "Ratings")
@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Ratings {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int ratingId;

    @ManyToOne
    @JoinColumn(name = "productId")
    private Products product;
    @ManyToOne
    @JoinColumn(name = "userId")
    private Users user;
    private int ratingValue;
    private String ratingContent;
    @Temporal(TemporalType.TIMESTAMP)
    private Date ratingDate;
}
