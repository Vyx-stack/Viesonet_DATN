package com.viesonet.entity;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "Products")
@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Products {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int productId;
    private String productName;
    private float originalPrice;
    private float promotion;
    private String description;
    private int viewsCount;
    private int ratingsCount;
    private int soldQuantity;
    private float height;
    private float width;
    private float weight;
    private String material;

    @ManyToOne
    @JoinColumn(name = "userId")
    private Users user;

    @OneToMany(mappedBy = "product")
    private List<ProductColors> productColors;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<ShoppingCart> shoppingCart;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<ViolationProducts> violationProducts;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<FavoriteProducts> favoriteProducts;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<Media> media;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<OrderDetails> orderDetails;

    @JsonIgnore
    @OneToMany(mappedBy = "product")
    private List<Ratings> ratings;
}
