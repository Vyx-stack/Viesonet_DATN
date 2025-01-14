package com.viesonet.entity;

import java.util.Date;

import jakarta.persistence.Entity;
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
@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "FavoriteProducts")
public class FavoriteProducts {
    @Id
    @ManyToOne
    @JoinColumn(name = "productId")
    private Products product;
    @Id
    @ManyToOne
    @JoinColumn(name = "userId")
    private Users user;

    @Temporal(TemporalType.TIMESTAMP)
    private Date favoriteDate;
}
